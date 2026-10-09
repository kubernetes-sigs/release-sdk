/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	sgsign "github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

const (
	// simpleSigningMediaType is the media type of legacy cosign image
	// signature layers.
	simpleSigningMediaType types.MediaType = "application/vnd.dev.cosign.simplesigning.v1+json"

	// Annotations of the legacy cosign image signature layers.
	signatureAnnotation   = "dev.cosignproject.cosign/signature"
	certificateAnnotation = "dev.sigstore.cosign/certificate"
	bundleAnnotation      = "dev.sigstore.cosign/bundle"

	// maxPayloadSize is the maximum accepted size of a signature payload.
	maxPayloadSize = 1 << 20

	userAgent = "k8s-release-sdk"
)

// nameOptions returns the options to parse image references.
func (o *Options) nameOptions() []name.Option {
	if o.AllowInsecure {
		return []name.Option{name.Insecure}
	}

	return nil
}

// remoteOptions returns the options to access image registries.
func (o *Options) remoteOptions(ctx context.Context) []remote.Option {
	keychain := authn.NewMultiKeychain(authn.DefaultKeychain, google.Keychain, github.Keychain)

	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(keychain),
		remote.WithUserAgent(userAgent),
	}

	if o.AllowInsecure {
		if t, ok := remote.DefaultTransport.(*http.Transport); ok {
			t = t.Clone()
			t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicitly requested
			opts = append(opts, remote.WithTransport(t))
		}
	}

	return opts
}

// signatureTag returns the legacy cosign signature tag for an image digest.
func signatureTag(digest name.Digest) name.Tag {
	return digest.Context().Tag(signatureTagName(digest.DigestStr()))
}

// signatureTagName returns the legacy cosign signature tag name for a digest
// string like "sha256:abc".
func signatureTagName(digest string) string {
	return strings.Replace(digest, ":", "-", 1) + sigExt
}

// isNotFound returns true if the error indicates a missing manifest. Other
// errors like an unknown repository or missing permissions do not count.
func isNotFound(err error) bool {
	var transportErr *transport.Error
	if !errors.As(err, &transportErr) {
		return false
	}

	for _, e := range transportErr.Errors {
		if e.Code == transport.ManifestUnknownErrorCode {
			return true
		}
	}

	return false
}

// digestsToSign resolves the reference to its digest, and includes the
// digests of all contained images if the signing is recursive.
func digestsToSign(ref name.Reference, recursive bool, ropts []remote.Option) ([]name.Digest, error) {
	desc, err := remote.Get(ref, ropts...)
	if err != nil {
		return nil, fmt.Errorf("get image descriptor: %w", err)
	}

	digest := ref.Context().Digest(desc.Digest.String())

	if !recursive || !desc.MediaType.IsIndex() {
		return []name.Digest{digest}, nil
	}

	index, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("get image index: %w", err)
	}

	children, err := indexDigests(ref.Context(), index)
	if err != nil {
		return nil, err
	}

	return append([]name.Digest{digest}, children...), nil
}

// indexDigests returns the digests of all manifests within the index,
// including nested ones.
func indexDigests(repo name.Repository, index v1.ImageIndex) ([]name.Digest, error) {
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("get index manifest: %w", err)
	}

	digests := []name.Digest{}

	for i := range manifest.Manifests {
		desc := &manifest.Manifests[i]

		switch {
		case desc.MediaType.IsIndex():
			child, err := index.ImageIndex(desc.Digest)
			if err != nil {
				return nil, fmt.Errorf("get nested image index %s: %w", desc.Digest, err)
			}

			childDigests, err := indexDigests(repo, child)
			if err != nil {
				return nil, err
			}

			digests = append(digests, repo.Digest(desc.Digest.String()))
			digests = append(digests, childDigests...)

		case desc.MediaType.IsImage():
			digests = append(digests, repo.Digest(desc.Digest.String()))
		}
	}

	return digests, nil
}

// parseAnnotations converts key=value pairs into a map.
func parseAnnotations(annotations []string) (map[string]any, error) {
	if len(annotations) == 0 {
		return nil, nil
	}

	res := make(map[string]any, len(annotations))

	for _, annotation := range annotations {
		key, value, ok := strings.Cut(annotation, "=")
		if !ok {
			return nil, fmt.Errorf("unable to parse annotation %q: expected key=value", annotation)
		}

		res[key] = value
	}

	return res, nil
}

// signImage signs all requested digests of the reference by using the legacy
// cosign signature format.
func (d *defaultImpl) signImage(ctx context.Context, opts *Options, identityToken, reference string) error {
	ref, err := name.ParseReference(reference, opts.nameOptions()...)
	if err != nil {
		return fmt.Errorf("parse reference: %w", err)
	}

	annotations, err := parseAnnotations(opts.Annotations)
	if err != nil {
		return err
	}

	ropts := opts.remoteOptions(ctx)

	digests, err := digestsToSign(ref, opts.Recursive, ropts)
	if err != nil {
		return err
	}

	kp, err := signingKeypair(opts)
	if err != nil {
		return fmt.Errorf("get signing keypair: %w", err)
	}

	// All digests share the same keypair and certificate.
	bundleOpts, err := d.bundleOptions(ctx, opts, identityToken)
	if err != nil {
		return err
	}

	for i, digest := range digests {
		sig, certPEM, err := signDigest(opts, kp, bundleOpts, digest, annotations, ropts)
		if err != nil {
			return fmt.Errorf("sign %s: %w", digest, err)
		}

		// The outputs refer to the requested reference, not to the
		// recursively signed images.
		if i == 0 {
			if err := writeImageOutputs(opts, sig, certPEM); err != nil {
				return err
			}
		}
	}

	return nil
}

// writeImageOutputs writes the base64 encoded signature and the PEM
// certificate of an image signature to the configured output paths, like
// cosign does.
func writeImageOutputs(opts *Options, sig string, certPEM []byte) error {
	if opts.OutputSignaturePath != "" {
		if err := os.WriteFile(opts.OutputSignaturePath, []byte(sig), signatureFileMode); err != nil {
			return fmt.Errorf("write signature: %w", err)
		}
	}

	if opts.OutputCertificatePath != "" && certPEM != nil {
		if err := os.WriteFile(opts.OutputCertificatePath, certPEM, signatureFileMode); err != nil {
			return fmt.Errorf("write certificate: %w", err)
		}
	}

	return nil
}

// signDigest signs the digest and appends the signature to its signature
// image. It returns the base64 encoded signature and the PEM certificate for
// keyless signing. Key based signatures are not added again if the same
// payload has already been signed with that key.
func signDigest(
	opts *Options,
	kp sgsign.Keypair,
	bundleOpts *sgsign.BundleOptions,
	digest name.Digest,
	annotations map[string]any,
	ropts []remote.Option,
) (sig string, certPEM []byte, err error) {
	payloadBytes, err := payload.Cosign{
		Image:           digest,
		ClaimedIdentity: opts.SignContainerIdentity,
		Annotations:     annotations,
	}.MarshalJSON()
	if err != nil {
		return "", nil, fmt.Errorf("marshal payload: %w", err)
	}

	tag := signatureTag(digest)

	base, err := signatureImage(tag, ropts)
	if err != nil {
		return "", nil, err
	}

	if key, ok := kp.(*keypair); ok && opts.PrivateKeyPath != "" {
		existing, err := existingSignature(base, payloadBytes, key)
		if err != nil {
			return "", nil, err
		}

		if existing != "" {
			return existing, nil, nil
		}
	}

	b, err := signBundle(kp, bundleOpts, payloadBytes)
	if err != nil {
		return "", nil, err
	}

	sig = base64.StdEncoding.EncodeToString(b.GetMessageSignature().GetSignature())
	layerAnnotations := map[string]string{signatureAnnotation: sig}

	if certDER := certificateDER(b); certDER != nil {
		certPEM = certificatePEM(certDER)
		layerAnnotations[certificateAnnotation] = string(certPEM)
	}

	if entries := b.GetVerificationMaterial().GetTlogEntries(); len(entries) > 0 {
		rekorBundle, err := rekorBundleFromEntry(entries[0])
		if err != nil {
			return "", nil, err
		}

		rekorBundleBytes, err := json.Marshal(rekorBundle)
		if err != nil {
			return "", nil, fmt.Errorf("marshal rekor bundle: %w", err)
		}

		layerAnnotations[bundleAnnotation] = string(rekorBundleBytes)
	}

	if err := appendSignature(tag, base, payloadBytes, layerAnnotations, ropts); err != nil {
		return "", nil, err
	}

	return sig, certPEM, nil
}

// signatureImage returns the existing signature image or an empty one.
func signatureImage(tag name.Tag, ropts []remote.Option) (v1.Image, error) {
	img, err := remote.Image(tag, ropts...)
	if err == nil {
		return img, nil
	}

	// The image has been resolved in the same repository, so any 404 means
	// that there are no signatures yet, like in cosign.
	var transportErr *transport.Error
	if !isNotFound(err) && (!errors.As(err, &transportErr) || transportErr.StatusCode != http.StatusNotFound) {
		return nil, fmt.Errorf("get signature image: %w", err)
	}

	return mutate.ConfigMediaType(mutate.MediaType(empty.Image, types.OCIManifestSchema1), types.OCIConfigJSON), nil
}

// existingSignature returns the base64 encoded signature of a layer with the
// same payload and a transparency log bundle which verifies with the key, or
// an empty string if there is none.
func existingSignature(img v1.Image, payloadBytes []byte, key *keypair) (string, error) {
	manifest, err := img.Manifest()
	if err != nil {
		return "", fmt.Errorf("get signature manifest: %w", err)
	}

	verifier, err := signature.LoadVerifier(key.GetPublicKey(), key.algDetails.GetHashType())
	if err != nil {
		return "", fmt.Errorf("load verifier: %w", err)
	}

	payloadDigest := sha256.Sum256(payloadBytes)
	payloadHex := hex.EncodeToString(payloadDigest[:])

	for i := range manifest.Layers {
		desc := &manifest.Layers[i]
		if desc.MediaType != simpleSigningMediaType || desc.Digest.Hex != payloadHex {
			continue
		}

		sig, err := base64.StdEncoding.DecodeString(desc.Annotations[signatureAnnotation])
		if err != nil {
			continue
		}

		// Signatures without a transparency log bundle do not verify by
		// default, so they must not prevent adding a new one.
		if desc.Annotations[bundleAnnotation] != "" &&
			verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(payloadBytes)) == nil {
			return desc.Annotations[signatureAnnotation], nil
		}
	}

	return "", nil
}

// appendSignature appends the signature layer to the signature image and
// writes it to the tag.
func appendSignature(
	tag name.Tag, base v1.Image, payloadBytes []byte, annotations map[string]string, ropts []remote.Option,
) error {
	img, err := mutate.Append(base, mutate.Addendum{
		Layer:       static.NewLayer(payloadBytes, simpleSigningMediaType),
		Annotations: annotations,
	})
	if err != nil {
		return fmt.Errorf("append signature layer: %w", err)
	}

	if err := remote.Write(tag, img, ropts...); err != nil {
		return fmt.Errorf("write signature image: %w", err)
	}

	return nil
}

// verifyImage verifies that at least one legacy cosign signature of the
// reference is valid and returns the verified digest.
func (d *defaultImpl) verifyImage(ctx context.Context, opts *Options, reference string) (string, error) {
	ref, err := name.ParseReference(reference, opts.nameOptions()...)
	if err != nil {
		return "", fmt.Errorf("parse reference: %w", err)
	}

	ropts := opts.remoteOptions(ctx)

	desc, err := remote.Head(ref, ropts...)
	if err != nil {
		// Not every registry supports HEAD for manifests, fall back to GET
		// like crane.Digest does.
		getDesc, getErr := remote.Get(ref, ropts...)
		if getErr != nil {
			return "", fmt.Errorf("get image descriptor: %w", errors.Join(err, getErr))
		}

		desc = &getDesc.Descriptor
	}

	digest := ref.Context().Digest(desc.Digest.String())

	sigImage, err := remote.Image(signatureTag(digest), ropts...)
	if err != nil {
		if isNotFound(err) {
			return "", fmt.Errorf("no signatures found for %s", digest)
		}

		return "", fmt.Errorf("get signature image: %w", err)
	}

	manifest, err := sigImage.Manifest()
	if err != nil {
		return "", fmt.Errorf("get signature manifest: %w", err)
	}

	errs := []error{}

	for i := range manifest.Layers {
		desc := &manifest.Layers[i]
		if desc.MediaType != simpleSigningMediaType {
			continue
		}

		// A broken layer must not hide a valid signature in another one.
		if err := d.verifyLayer(opts, sigImage, desc, digest); err != nil {
			errs = append(errs, fmt.Errorf("signature layer %s: %w", desc.Digest, err))

			continue
		}

		return digest.DigestStr(), nil
	}

	if len(errs) == 0 {
		return "", fmt.Errorf("no signatures found for %s", digest)
	}

	return "", fmt.Errorf("no valid signature found for %s: %w", digest, errors.Join(errs...))
}

// verifyLayer reads and verifies a single signature layer of the signature
// image.
func (d *defaultImpl) verifyLayer(opts *Options, sigImage v1.Image, desc *v1.Descriptor, digest name.Digest) error {
	layer, err := sigImage.LayerByDigest(desc.Digest)
	if err != nil {
		return fmt.Errorf("get signature layer: %w", err)
	}

	payloadBytes, err := layerPayload(layer)
	if err != nil {
		return err
	}

	return d.verifySignatureLayer(opts, digest, payloadBytes, desc.Annotations)
}

func layerPayload(layer v1.Layer) ([]byte, error) {
	rc, err := layer.Compressed()
	if err != nil {
		return nil, fmt.Errorf("read signature layer: %w", err)
	}
	defer rc.Close()

	payloadBytes, err := io.ReadAll(io.LimitReader(rc, maxPayloadSize+1))
	if err != nil {
		return nil, fmt.Errorf("read signature payload: %w", err)
	}

	if len(payloadBytes) > maxPayloadSize {
		return nil, fmt.Errorf("signature payload exceeds %d bytes", maxPayloadSize)
	}

	return payloadBytes, nil
}

// verifySignatureLayer verifies a single legacy cosign signature layer.
func (d *defaultImpl) verifySignatureLayer(
	opts *Options, digest name.Digest, payloadBytes []byte, annotations map[string]string,
) error {
	sig, err := base64.StdEncoding.DecodeString(annotations[signatureAnnotation])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	var certDER []byte

	if opts.PublicKeyPath == "" {
		certPEM := annotations[certificateAnnotation]
		if certPEM == "" {
			return errors.New("no certificate found")
		}

		certDER, err = parseCertificatePEM([]byte(certPEM))
		if err != nil {
			return err
		}
	}

	var entries []*protorekor.TransparencyLogEntry

	if !opts.IgnoreTlog {
		rekorBundleJSON := annotations[bundleAnnotation]
		if rekorBundleJSON == "" {
			return errors.New("no transparency log bundle found")
		}

		var rb rekorBundle
		if err := json.Unmarshal([]byte(rekorBundleJSON), &rb); err != nil {
			return fmt.Errorf("unmarshal transparency log bundle: %w", err)
		}

		entry, err := rb.entry()
		if err != nil {
			return err
		}

		entries = append(entries, entry)
	}

	payloadDigest := sha256.Sum256(payloadBytes)

	b, err := legacyBundle(sig, payloadDigest[:], certDER, entries)
	if err != nil {
		return err
	}

	if err := d.verifyBundle(opts, b, verify.WithArtifact(bytes.NewReader(payloadBytes)), !opts.IgnoreTlog); err != nil {
		return err
	}

	var p payload.SimpleContainerImage
	if err := json.NewDecoder(bytes.NewReader(payloadBytes)).Decode(&p); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	if p.Critical.Type != payload.CosignSignatureType {
		return fmt.Errorf("unexpected payload type: %s", p.Critical.Type)
	}

	if p.Critical.Image.DockerManifestDigest != digest.DigestStr() {
		return fmt.Errorf(
			"payload digest %s does not match image digest %s",
			p.Critical.Image.DockerManifestDigest, digest.DigestStr(),
		)
	}

	return nil
}
