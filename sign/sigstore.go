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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgsign "github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	// tufRootEnv can be used to set a custom TUF cache directory, like in
	// cosign.
	tufRootEnv = "TUF_ROOT"

	// tufMirrorEnv can be used to set a custom TUF mirror, like in cosign.
	tufMirrorEnv = "TUF_MIRROR"

	// tufRootJSONEnv can be used to set the TUF root of a custom mirror, like
	// in cosign.
	tufRootJSONEnv = "TUF_ROOT_JSON"

	// defaultRekorURL is the public Rekor v1 instance, which is used to look
	// up existing entries if the signing config does not contain any v1
	// instance.
	defaultRekorURL = "https://rekor.sigstore.dev"

	// trustedMaterialTTL is the duration after which the trusted root and
	// signing config get refreshed.
	trustedMaterialTTL = 24 * time.Hour
)

// rekorV1 is the only supported Rekor API version, because the legacy
// signature formats rely on its signed entry timestamps.
var rekorV1 = []uint32{1}

// keypair implements the sigstore-go sign.Keypair interface for existing
// private keys.
type keypair struct {
	signer     crypto.Signer
	algDetails signature.AlgorithmDetails
	hint       []byte
}

var _ sgsign.Keypair = (*keypair)(nil)

// loadKeypair loads a PEM encoded (and optionally encrypted) private key.
func loadKeypair(path string, pf cryptoutils.PassFunc) (*keypair, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	if pf == nil {
		// An empty password matches the cosign default.
		pf = func(bool) ([]byte, error) { return []byte{}, nil }
	}

	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey(pemBytes, pf)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}

	return newKeypair(privateKey)
}

func newKeypair(privateKey crypto.PrivateKey) (*keypair, error) {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	keyDetails, err := cosignPublicKeyDetails(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("get public key details: %w", err)
	}

	algDetails, err := signature.GetAlgorithmDetails(keyDetails)
	if err != nil {
		return nil, fmt.Errorf("get algorithm details: %w", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	hashedBytes := sha256.Sum256(pubKeyBytes)

	return &keypair{
		signer:     signer,
		algDetails: algDetails,
		hint:       []byte(base64.StdEncoding.EncodeToString(hashedBytes[:])),
	}, nil
}

// cosignPublicKeyDetails returns the signing algorithm for a key, which uses
// SHA-256 for every ECDSA curve to stay compatible with cosign and the SHA-256
// based Rekor lookup and legacy bundles.
func cosignPublicKeyDetails(publicKey crypto.PublicKey) (protocommon.PublicKeyDetails, error) {
	if ecdsaKey, ok := publicKey.(*ecdsa.PublicKey); ok {
		switch ecdsaKey.Curve {
		case elliptic.P384():
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_256, nil //nolint:staticcheck // cosign compatibility
		case elliptic.P521():
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_256, nil //nolint:staticcheck // cosign compatibility
		}
	}

	return signature.GetDefaultPublicKeyDetails(publicKey)
}

func (k *keypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return k.algDetails.GetProtoHashType()
}

func (k *keypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return k.algDetails.GetSignatureAlgorithm()
}

func (k *keypair) GetHint() []byte {
	return k.hint
}

func (k *keypair) GetKeyAlgorithm() string {
	switch k.algDetails.GetKeyType() {
	case signature.ECDSA:
		return "ECDSA"
	case signature.RSA:
		return "RSA"
	case signature.ED25519:
		return "ED25519"
	case signature.MLDSA:
		return "MLDSA"
	default:
		return ""
	}
}

func (k *keypair) GetPublicKey() crypto.PublicKey {
	return k.signer.Public()
}

func (k *keypair) GetPublicKeyPem() (string, error) {
	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(k.signer.Public())
	if err != nil {
		return "", err
	}

	return string(pubKeyBytes), nil
}

func (k *keypair) SignData(_ context.Context, data []byte) (sig, digest []byte, err error) {
	hf := k.algDetails.GetHashType()
	dataToSign := data

	// Pure Ed25519 takes the data and hashes during signing.
	if hf != crypto.Hash(0) {
		hasher := hf.New()
		hasher.Write(data)
		dataToSign = hasher.Sum(nil)
	}

	sig, err = k.signer.Sign(rand.Reader, dataToSign, hf)
	if err != nil {
		return nil, nil, err
	}

	return sig, dataToSign, nil
}

// signingKeypair returns the keypair for signing, which is either loaded from
// the configured private key or an ephemeral one for keyless signing.
func signingKeypair(opts *Options) (*keypair, error) {
	if opts.PrivateKeyPath != "" {
		return loadKeypair(opts.PrivateKeyPath, opts.PassFunc)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	return newKeypair(privateKey)
}

// prehashedKeypair signs a precomputed SHA-256 artifact digest directly, which
// avoids reading the whole artifact into memory. Everything else, like the
// Fulcio proof of possession, gets signed by the wrapped keypair.
type prehashedKeypair struct {
	*keypair

	digest []byte
}

// prehashed returns a keypair which signs the SHA-256 digest directly, or
// false if the signing algorithm does not hash with SHA-256 (like pure
// Ed25519).
func (k *keypair) prehashed(digest []byte) (*prehashedKeypair, bool) {
	if k.algDetails.GetHashType() != crypto.SHA256 {
		return nil, false
	}

	return &prehashedKeypair{keypair: k, digest: digest}, true
}

func (k *prehashedKeypair) SignData(ctx context.Context, data []byte) (sig, digest []byte, err error) {
	if !bytes.Equal(data, k.digest) {
		return k.keypair.SignData(ctx, data)
	}

	sig, err = k.signer.Sign(rand.Reader, k.digest, crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}

	return sig, k.digest, nil
}

// publicKeyMaterial loads the configured public key as trusted material.
func publicKeyMaterial(path string) (root.TrustedMaterial, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public key: %w", err)
	}

	// cosign uses SHA-256 for all key based signatures.
	verifier, err := signature.LoadVerifier(publicKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("load verifier: %w", err)
	}

	key := root.NewExpiringKey(verifier, time.Time{}, time.Time{})

	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		return key, nil
	}), nil
}

// tufOptions returns the TUF options to fetch the trusted root and signing
// config. The cache directory, mirror and root are selected like in cosign,
// including the remote.json written by `cosign initialize`.
func tufOptions() (*tuf.Options, error) {
	opts := tuf.DefaultOptions()
	if dir := os.Getenv(tufRootEnv); dir != "" {
		opts.CachePath = dir
	}

	if mirror := os.Getenv(tufMirrorEnv); mirror != "" {
		opts.RepositoryBaseURL = mirror
	} else if remoteJSON, err := os.ReadFile(filepath.Join(opts.CachePath, "remote.json")); err == nil {
		remote := map[string]string{}
		if err := json.Unmarshal(remoteJSON, &remote); err != nil {
			return nil, fmt.Errorf("unmarshal remote.json: %w", err)
		}

		opts.RepositoryBaseURL = remote["mirror"]
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read remote.json: %w", err)
	}

	if opts.RepositoryBaseURL == tuf.DefaultMirror {
		return opts, nil
	}

	// A custom mirror must not use the embedded public-good root.
	rootPath := os.Getenv(tufRootJSONEnv)
	if rootPath == "" {
		rootPath = filepath.Join(opts.CachePath, tuf.URLToPath(opts.RepositoryBaseURL), "root.json")
	}

	rootJSON, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, fmt.Errorf("read TUF root for mirror %s: %w", opts.RepositoryBaseURL, err)
	}

	opts.Root = rootJSON

	return opts, nil
}

// loadTUF refreshes the TUF metadata once per TTL and caches the trusted
// root and signing config derived from it. Must be called with d.mu held.
func (d *defaultImpl) loadTUF() error {
	if d.tufClient != nil && time.Since(d.tufFetched) < trustedMaterialTTL {
		return nil
	}

	tufOpts, err := tufOptions()
	if err != nil {
		return err
	}

	client, err := tuf.New(tufOpts)
	if err != nil {
		return fmt.Errorf("create TUF client: %w", err)
	}

	trustedRoot, err := root.GetTrustedRoot(client)
	if err != nil {
		return fmt.Errorf("get trusted root: %w", err)
	}

	d.tufClient = client
	d.tufFetched = time.Now()
	d.trustedRoot = trustedRoot
	d.signingConf = nil

	return nil
}

// trustedMaterial returns the cached trusted root.
func (d *defaultImpl) trustedMaterial() (*root.TrustedRoot, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.loadTUF(); err != nil {
		return nil, err
	}

	return d.trustedRoot, nil
}

// signingConfig returns the cached signing config.
func (d *defaultImpl) signingConfig() (*root.SigningConfig, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.loadTUF(); err != nil {
		return nil, err
	}

	if d.signingConf == nil {
		signingConf, err := root.GetSigningConfig(d.tufClient)
		if err != nil {
			return nil, fmt.Errorf("get signing config: %w", err)
		}

		d.signingConf = signingConf
	}

	return d.signingConf, nil
}

// rekorReadURL returns the URL of the Rekor v1 instance to look up existing
// entries. Lookups have to keep working after the log stopped accepting new
// entries, so the validity period is ignored.
func (d *defaultImpl) rekorReadURL() (string, error) {
	signingConf, err := d.signingConfig()
	if err != nil {
		return "", err
	}

	var res *root.Service

	for _, s := range signingConf.RekorLogURLs() {
		if s.MajorAPIVersion == 1 && (res == nil || s.ValidityPeriodStart.After(res.ValidityPeriodStart)) {
			res = &s
		}
	}

	if res == nil {
		return defaultRekorURL, nil
	}

	return res.URL, nil
}

// rekorService returns the Rekor v1 instance of the signing config to upload
// new entries.
func (d *defaultImpl) rekorService() (root.Service, error) {
	signingConf, err := d.signingConfig()
	if err != nil {
		return root.Service{}, err
	}

	service, err := root.SelectService(signingConf.RekorLogURLs(), rekorV1, time.Now())
	if err != nil {
		return root.Service{}, fmt.Errorf(
			"select rekor service: legacy signatures require Rekor v1, which the signing config no longer offers: %w", err,
		)
	}

	return service, nil
}

// bundleOptions returns the options to sign bundles, which upload to Rekor
// and use Fulcio for keyless signing if the identity token is set.
func (d *defaultImpl) bundleOptions(
	ctx context.Context, opts *Options, identityToken string,
) (*sgsign.BundleOptions, error) {
	rekorService, err := d.rekorService()
	if err != nil {
		return nil, err
	}

	bundleOpts := &sgsign.BundleOptions{
		Context: ctx,
		TransparencyLogs: []sgsign.Transparency{sgsign.NewRekor(&sgsign.RekorOptions{
			BaseURL: rekorService.URL,
			Timeout: opts.Timeout,
			Retries: opts.MaxRetries,
			Version: rekorService.MajorAPIVersion,
		})},
	}

	if identityToken == "" {
		return bundleOpts, nil
	}

	signingConf, err := d.signingConfig()
	if err != nil {
		return nil, err
	}

	fulcioService, err := root.SelectService(
		signingConf.FulcioCertificateAuthorityURLs(), sgsign.FulcioAPIVersions, time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("select fulcio service: %w", err)
	}

	bundleOpts.CertificateProvider = &cachingCertificateProvider{
		provider: sgsign.NewFulcio(&sgsign.FulcioOptions{
			BaseURL: fulcioService.URL,
			Timeout: opts.Timeout,
			Retries: opts.MaxRetries,
		}),
	}
	bundleOpts.CertificateProviderOptions = &sgsign.CertificateProviderOptions{IDToken: identityToken}

	return bundleOpts, nil
}

// cachingCertificateProvider requests a single certificate, which allows
// signing multiple artifacts with the same keypair.
type cachingCertificateProvider struct {
	provider sgsign.CertificateProvider
	mu       sync.Mutex
	cert     []byte
}

func (c *cachingCertificateProvider) GetCertificate(
	ctx context.Context, kp sgsign.Keypair, opts *sgsign.CertificateProviderOptions,
) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cert != nil {
		return c.cert, nil
	}

	cert, err := c.provider.GetCertificate(ctx, kp, opts)
	if err != nil {
		return nil, err
	}

	c.cert = cert

	return cert, nil
}

// signBundle signs the data and uploads the signature to Rekor.
func signBundle(kp sgsign.Keypair, bundleOpts *sgsign.BundleOptions, data []byte) (*protobundle.Bundle, error) {
	b, err := sgsign.Bundle(&sgsign.PlainData{Data: data}, kp, *bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("sign bundle: %w", err)
	}

	return b, nil
}

// rekorBundle is the legacy cosign representation of a Rekor entry including
// its signed entry timestamp.
type rekorBundle struct {
	SignedEntryTimestamp []byte       `json:"SignedEntryTimestamp"` //nolint:tagliatelle // legacy cosign format
	Payload              rekorPayload `json:"Payload"`              //nolint:tagliatelle // legacy cosign format
}

type rekorPayload struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogIndex       int64  `json:"logIndex"`
	LogID          string `json:"logID"` //nolint:tagliatelle // legacy cosign format
}

// rekorBundleFromEntry converts a transparency log entry into the legacy
// cosign Rekor bundle.
func rekorBundleFromEntry(entry *protorekor.TransparencyLogEntry) (*rekorBundle, error) {
	set := entry.GetInclusionPromise().GetSignedEntryTimestamp()
	if len(set) == 0 {
		return nil, errors.New("transparency log entry has no signed entry timestamp")
	}

	return &rekorBundle{
		SignedEntryTimestamp: set,
		Payload: rekorPayload{
			Body:           base64.StdEncoding.EncodeToString(entry.GetCanonicalizedBody()),
			IntegratedTime: entry.GetIntegratedTime(),
			LogIndex:       entry.GetLogIndex(),
			LogID:          hex.EncodeToString(entry.GetLogId().GetKeyId()),
		},
	}, nil
}

// entry converts the legacy cosign Rekor bundle into a transparency log entry
// with an inclusion promise.
func (r *rekorBundle) entry() (*protorekor.TransparencyLogEntry, error) {
	body, err := base64.StdEncoding.DecodeString(r.Payload.Body)
	if err != nil {
		return nil, fmt.Errorf("decode rekor entry body: %w", err)
	}

	var kindVersion struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}

	if err := json.Unmarshal(body, &kindVersion); err != nil {
		return nil, fmt.Errorf("unmarshal rekor entry body: %w", err)
	}

	logID, err := hex.DecodeString(r.Payload.LogID)
	if err != nil {
		return nil, fmt.Errorf("decode rekor log ID: %w", err)
	}

	return &protorekor.TransparencyLogEntry{
		LogIndex:          r.Payload.LogIndex,
		LogId:             &protocommon.LogId{KeyId: logID},
		KindVersion:       &protorekor.KindVersion{Kind: kindVersion.Kind, Version: kindVersion.APIVersion},
		IntegratedTime:    r.Payload.IntegratedTime,
		InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: r.SignedEntryTimestamp},
		CanonicalizedBody: body,
	}, nil
}

// legacyBundle assembles a v0.1 sigstore bundle from detached signature
// components and the SHA256 digest of the signed artifact, which allows
// verifying them with sigstore-go. The certificate can be nil for key based
// signatures.
func legacyBundle(
	sig, digest, certDER []byte, entries []*protorekor.TransparencyLogEntry,
) (*bundle.Bundle, error) {
	mediaType, err := bundle.MediaTypeString("0.1")
	if err != nil {
		return nil, fmt.Errorf("get bundle media type: %w", err)
	}

	verificationMaterial := &protobundle.VerificationMaterial{TlogEntries: entries}
	if certDER != nil {
		verificationMaterial.Content = &protobundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &protocommon.X509CertificateChain{
				Certificates: []*protocommon.X509Certificate{{RawBytes: certDER}},
			},
		}
	} else {
		verificationMaterial.Content = &protobundle.VerificationMaterial_PublicKey{
			PublicKey: &protocommon.PublicKeyIdentifier{},
		}
	}

	b, err := bundle.NewBundle(&protobundle.Bundle{
		MediaType:            mediaType,
		VerificationMaterial: verificationMaterial,
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    digest,
				},
				Signature: sig,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create bundle: %w", err)
	}

	return b, nil
}

// verifyBundle verifies the bundle against the artifact by using the
// configured public key or certificate identity.
func (d *defaultImpl) verifyBundle(
	opts *Options, b *bundle.Bundle, artifactPolicy verify.ArtifactPolicyOption, useTlog bool,
) error {
	var (
		trustedMaterial root.TrustedMaterialCollection
		verifierOpts    []verify.VerifierOption
		policyOpts      []verify.PolicyOption
	)

	keyBased := opts.PublicKeyPath != ""

	// Key based verification without transparency log works offline.
	if !keyBased || useTlog {
		trustedRoot, err := d.trustedMaterial()
		if err != nil {
			return err
		}

		trustedMaterial = append(trustedMaterial, trustedRoot)
	}

	if keyBased {
		keyMaterial, err := publicKeyMaterial(opts.PublicKeyPath)
		if err != nil {
			return err
		}

		trustedMaterial = append(trustedMaterial, keyMaterial)
		policyOpts = append(policyOpts, verify.WithKey())
	} else {
		identity, err := verify.NewShortCertificateIdentity(
			opts.CertOidcIssuer, opts.CertOidcIssuerRegexp, opts.CertIdentity, opts.CertIdentityRegexp,
		)
		if err != nil {
			return fmt.Errorf("create certificate identity: %w", err)
		}

		policyOpts = append(policyOpts, verify.WithCertificateIdentity(identity))

		if !opts.IgnoreSCT {
			verifierOpts = append(verifierOpts, verify.WithSignedCertificateTimestamps(1))
		}
	}

	if useTlog {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}

	switch {
	case keyBased:
		verifierOpts = append(verifierOpts, verify.WithNoObserverTimestamps())
	case useTlog:
		verifierOpts = append(verifierOpts, verify.WithIntegratedTimestamps(1))
	default:
		verifierOpts = append(verifierOpts, verify.WithCurrentTime())
	}

	verifier, err := verify.NewVerifier(trustedMaterial, verifierOpts...)
	if err != nil {
		return fmt.Errorf("create verifier: %w", err)
	}

	if _, err := verifier.Verify(b, verify.NewPolicy(artifactPolicy, policyOpts...)); err != nil {
		if !keyBased && !useTlog {
			return fmt.Errorf("verify bundle without transparency log, which requires a certificate that is still valid: %w", err)
		}

		return fmt.Errorf("verify bundle: %w", err)
	}

	return nil
}

// certificateDER returns the DER encoded leaf certificate of a signed bundle,
// or nil if the bundle has been signed with a key.
func certificateDER(b *protobundle.Bundle) []byte {
	if cert := b.GetVerificationMaterial().GetCertificate(); cert != nil {
		return cert.GetRawBytes()
	}

	if chain := b.GetVerificationMaterial().GetX509CertificateChain(); chain != nil && len(chain.GetCertificates()) > 0 {
		return chain.GetCertificates()[0].GetRawBytes()
	}

	return nil
}

// certificatePEM converts a DER encoded certificate into PEM.
func certificatePEM(der []byte) []byte {
	return cryptoutils.PEMEncode(cryptoutils.CertificatePEMType, der)
}

// parseCertificatePEM returns the DER encoded leaf certificate of a PEM
// encoded certificate chain.
func parseCertificatePEM(pemBytes []byte) ([]byte, error) {
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal certificate: %w", err)
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificate found")
	}

	return certs[0].Raw, nil
}
