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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	rekorgenerated "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/tle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// ErrTlogEntryNotFound is returned if no transparency log entry matches a
// file signature.
var ErrTlogEntryNotFound = errors.New("no matching transparency log entry found")

const (
	// signatureFileMode is the file mode of written signatures and
	// certificates.
	signatureFileMode = 0o644
)

// signFile signs the file and writes the base64 encoded signature as well as
// the base64 encoded PEM certificate (for keyless signing) to the configured
// output paths.
func (d *defaultImpl) signFile(ctx context.Context, opts *Options, identityToken, path string) error {
	kp, err := signingKeypair(opts)
	if err != nil {
		return fmt.Errorf("get signing keypair: %w", err)
	}

	bundleOpts, err := d.bundleOptions(ctx, opts, identityToken)
	if err != nil {
		return err
	}

	digest, err := fileSHA256(path)
	if err != nil {
		return err
	}

	var b *protobundle.Bundle

	// Sign the digest if possible, which avoids reading the whole file
	// into memory.
	if prehashedKp, ok := kp.prehashed(digest); ok {
		b, err = signBundle(prehashedKp, bundleOpts, digest)
	} else {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read file: %w", readErr)
		}

		b, err = signBundle(kp, bundleOpts, data)
	}

	if err != nil {
		return err
	}

	sig := base64.StdEncoding.EncodeToString(b.GetMessageSignature().GetSignature())
	if err := os.WriteFile(opts.OutputSignaturePath, []byte(sig), signatureFileMode); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}

	if certDER := certificateDER(b); certDER != nil && opts.OutputCertificatePath != "" {
		cert := base64.StdEncoding.EncodeToString(certificatePEM(certDER))
		if err := os.WriteFile(opts.OutputCertificatePath, []byte(cert), signatureFileMode); err != nil {
			return fmt.Errorf("write certificate: %w", err)
		}
	}

	return nil
}

// fileSHA256 returns the SHA-256 digest of a file without reading it into
// memory.
func fileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return nil, fmt.Errorf("hash file: %w", err)
	}

	return hasher.Sum(nil), nil
}

// verifyFile verifies the file digest by using the configured signature and
// certificate paths. The matching Rekor entry gets looked up if the
// transparency log should be used.
func (d *defaultImpl) verifyFile(ctx context.Context, opts *Options, fileSHA256 string, useTlog bool) error {
	digest, err := hex.DecodeString(fileSHA256)
	if err != nil {
		return fmt.Errorf("decode file digest: %w", err)
	}

	sig, err := readSignature(opts.OutputSignaturePath)
	if err != nil {
		return err
	}

	var (
		certDER     []byte
		verifierPEM []byte
	)

	if opts.PublicKeyPath == "" {
		certDER, err = readCertificate(opts.OutputCertificatePath)
		if err != nil {
			return err
		}

		verifierPEM = certificatePEM(certDER)
	} else {
		verifierPEM, err = os.ReadFile(opts.PublicKeyPath)
		if err != nil {
			return fmt.Errorf("read public key: %w", err)
		}
	}

	var tlogEntries []*protorekor.TransparencyLogEntry

	if useTlog {
		entry, err := d.findTlogEntry(ctx, fileSHA256, sig, verifierPEM)
		if err != nil {
			return err
		}

		tlogEntries = append(tlogEntries, entry)
	}

	b, err := legacyBundle(sig, digest, certDER, tlogEntries)
	if err != nil {
		return err
	}

	return d.verifyBundle(opts, b, verify.WithArtifactDigest("sha256", digest), useTlog)
}

// readSignature reads a base64 encoded or raw signature file.
func readSignature(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(content)))
	if err != nil {
		// Raw signatures must not be trimmed.
		return content, nil //nolint:nilerr // raw signature
	}

	return sig, nil
}

// readCertificate reads a base64 encoded or raw PEM certificate file and
// returns the DER encoded leaf certificate.
func readCertificate(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}

	content = bytes.TrimSpace(content)

	if !bytes.HasPrefix(content, []byte("-----BEGIN")) {
		decoded, err := base64.StdEncoding.DecodeString(string(content))
		if err != nil {
			return nil, fmt.Errorf("decode certificate: %w", err)
		}

		content = decoded
	}

	return parseCertificatePEM(content)
}

// rekorClient returns a cached client to look up entries in the Rekor
// instance of the signing config.
func (d *defaultImpl) rekorClient() (*rekorgenerated.Rekor, error) {
	rekorURL, err := d.rekorReadURL()
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.rekor != nil && d.rekorClientURL == rekorURL {
		return d.rekor, nil
	}

	rc, err := rekorclient.GetRekorClient(rekorURL, rekorclient.WithUserAgent(userAgent))
	if err != nil {
		return nil, fmt.Errorf("create rekor client: %w", err)
	}

	d.rekor = rc
	d.rekorClientURL = rekorURL

	return rc, nil
}

// tlogEntryUUIDs returns the UUIDs of the Rekor entries for the SHA256 hash
// of an artifact, limited to the configured public key if set.
func (d *defaultImpl) tlogEntryUUIDs(ctx context.Context, opts *Options, artifactSHA256 string) ([]string, error) {
	rc, err := d.rekorClient()
	if err != nil {
		return nil, err
	}

	query := &models.SearchIndex{Hash: "sha256:" + artifactSHA256}

	if opts.PublicKeyPath != "" {
		publicKeyPEM, err := os.ReadFile(opts.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read public key: %w", err)
		}

		query.PublicKey = &models.SearchIndexPublicKey{
			Format:  new(models.SearchIndexPublicKeyFormatX509),
			Content: publicKeyPEM,
		}
		query.Operator = models.SearchIndexOperatorAnd
	}

	params := index.NewSearchIndexParams()
	params.Query = query

	res, err := rc.Index.SearchIndexContext(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("search rekor index: %w", err)
	}

	return res.GetPayload(), nil
}

// findTlogEntry returns the hashedrekord Rekor entry for the artifact hash,
// signature and PEM encoded certificate or public key.
func (d *defaultImpl) findTlogEntry(
	ctx context.Context, artifactSHA256 string, sig, verifierPEM []byte,
) (*protorekor.TransparencyLogEntry, error) {
	rc, err := d.rekorClient()
	if err != nil {
		return nil, err
	}

	query := &models.SearchLogQuery{}
	query.SetEntries([]models.ProposedEntry{&models.Hashedrekord{
		APIVersion: new("0.0.1"),
		Spec: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: new(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
					Value:     new(artifactSHA256),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: sig,
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: verifierPEM,
				},
			},
		},
	}})

	params := entries.NewSearchLogQueryParams()
	params.Entry = query

	res, err := rc.Entries.SearchLogQueryContext(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("search rekor log: %w", err)
	}

	for _, logEntry := range res.GetPayload() {
		for uuid, anon := range logEntry {
			entry, err := tle.GenerateTransparencyLogEntry(anon)
			if err != nil {
				return nil, fmt.Errorf("convert rekor entry %s: %w", uuid, err)
			}

			return entry, nil
		}
	}

	return nil, ErrTlogEntryNotFound
}
