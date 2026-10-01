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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func writeKeyPair(t *testing.T, pf cryptoutils.PassFunc) (privateKeyPath, publicKeyPath string) {
	t.Helper()

	privateBytes, publicBytes, err := cryptoutils.GeneratePEMEncodedECDSAKeyPair(elliptic.P256(), pf)
	require.NoError(t, err)

	dir := t.TempDir()
	privateKeyPath = filepath.Join(dir, "cosign.key")
	publicKeyPath = filepath.Join(dir, "cosign.pub")

	require.NoError(t, os.WriteFile(privateKeyPath, privateBytes, 0o600))
	require.NoError(t, os.WriteFile(publicKeyPath, publicBytes, 0o600))

	return privateKeyPath, publicKeyPath
}

func emptyPassword(bool) ([]byte, error) { return []byte{}, nil }

func TestKeypairSignVerifyOffline(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		genPass  cryptoutils.PassFunc
		loadPass cryptoutils.PassFunc
	}{
		{name: "unencrypted"},
		{name: "encrypted with empty password", genPass: emptyPassword},
		{
			name:     "encrypted with password",
			genPass:  func(bool) ([]byte, error) { return []byte("honk"), nil },
			loadPass: func(bool) ([]byte, error) { return []byte("honk"), nil },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			privateKeyPath, publicKeyPath := writeKeyPair(t, tc.genPass)

			kp, err := loadKeypair(privateKeyPath, tc.loadPass)
			require.NoError(t, err)
			require.Equal(t, "ECDSA", kp.GetKeyAlgorithm())
			require.NotEmpty(t, kp.GetHint())

			data := []byte("hello kubefolx!")
			sig, _, err := kp.SignData(t.Context(), data)
			require.NoError(t, err)

			digest := sha256.Sum256(data)
			b, err := legacyBundle(sig, digest[:], nil, nil)
			require.NoError(t, err)

			d := &defaultImpl{}
			opts := &Options{PublicKeyPath: publicKeyPath}
			require.NoError(t, d.verifyBundle(opts, b, verify.WithArtifact(bytes.NewReader(data)), false))
			require.NoError(t, d.verifyBundle(opts, b, verify.WithArtifactDigest("sha256", digest[:]), false))
			require.Error(t, d.verifyBundle(opts, b, verify.WithArtifact(bytes.NewReader([]byte("wrong"))), false))
		})
	}
}

func TestLoadKeypairWrongPassword(t *testing.T) {
	t.Parallel()

	privateKeyPath, _ := writeKeyPair(t, func(bool) ([]byte, error) { return []byte("honk"), nil })

	_, err := loadKeypair(privateKeyPath, nil)
	require.Error(t, err)
}

func TestRekorBundleRoundTrip(t *testing.T) {
	t.Parallel()

	entry := &protorekor.TransparencyLogEntry{
		LogIndex:          42,
		LogId:             &protocommon.LogId{KeyId: []byte{0xde, 0xad, 0xbe, 0xef}},
		KindVersion:       &protorekor.KindVersion{Kind: "hashedrekord", Version: "0.0.1"},
		IntegratedTime:    1700000000,
		InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: []byte("set")},
		CanonicalizedBody: []byte(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{}}`),
	}

	rb, err := rekorBundleFromEntry(entry)
	require.NoError(t, err)
	require.Equal(t, "deadbeef", rb.Payload.LogID)

	// The legacy cosign annotation format.
	rbJSON, err := json.Marshal(rb)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"SignedEntryTimestamp": "c2V0",
		"Payload": {
			"body": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6e319",
			"integratedTime": 1700000000,
			"logIndex": 42,
			"logID": "deadbeef"
		}
	}`, string(rbJSON))

	var decoded rekorBundle
	require.NoError(t, json.Unmarshal(rbJSON, &decoded))

	res, err := decoded.entry()
	require.NoError(t, err)
	require.True(t, proto.Equal(entry, res))

	_, err = rekorBundleFromEntry(&protorekor.TransparencyLogEntry{})
	require.Error(t, err)
}

func TestParseAnnotations(t *testing.T) {
	t.Parallel()

	res, err := parseAnnotations(nil)
	require.NoError(t, err)
	require.Nil(t, res)

	res, err = parseAnnotations([]string{"a=b", "c=d=e"})
	require.NoError(t, err)
	require.Equal(t, map[string]any{"a": "b", "c": "d=e"}, res)

	_, err = parseAnnotations([]string{"invalid"})
	require.Error(t, err)
}

func TestSignatureTag(t *testing.T) {
	t.Parallel()

	digest, err := name.NewDigest("registry.k8s.io/pause@sha256:" + strings.Repeat("a", 64))
	require.NoError(t, err)
	require.Equal(t, "registry.k8s.io/pause:sha256-"+strings.Repeat("a", 64)+".sig", signatureTag(digest).String())
}

func TestReadSignatureAndCertificate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	sigB64 := filepath.Join(dir, "b64.sig")
	require.NoError(t, os.WriteFile(sigB64, []byte(base64.StdEncoding.EncodeToString([]byte("sig"))+"\n"), 0o600))

	sig, err := readSignature(sigB64)
	require.NoError(t, err)
	require.Equal(t, []byte("sig"), sig)

	// Raw signatures may contain whitespace bytes, which must be kept.
	rawSig := []byte{0x30, 0x01, 0xff, 0x20}
	sigRaw := filepath.Join(dir, "raw.sig")
	require.NoError(t, os.WriteFile(sigRaw, rawSig, 0o600))

	sig, err = readSignature(sigRaw)
	require.NoError(t, err)
	require.Equal(t, rawSig, sig)

	_, err = readSignature(filepath.Join(dir, "missing"))
	require.Error(t, err)

	_, err = readCertificate(sigB64)
	require.Error(t, err)
}

func TestImageSignatureOffline(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(registry.New())
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	privateKeyPath, publicKeyPath := writeKeyPair(t, emptyPassword)
	opts := &Options{PublicKeyPath: publicKeyPath, IgnoreTlog: true, IgnoreSCT: true}
	ropts := opts.remoteOptions(t.Context())

	index, err := random.Index(64, 1, 2)
	require.NoError(t, err)

	ref, err := name.ParseReference(u.Host + "/test:latest")
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(ref, index, ropts...))

	digests, err := digestsToSign(ref, false, ropts)
	require.NoError(t, err)
	require.Len(t, digests, 1)

	digests, err = digestsToSign(ref, true, ropts)
	require.NoError(t, err)
	require.Len(t, digests, 3)

	d := &defaultImpl{}

	// Not signed yet
	require.ErrorContains(t, verifyImage(t, d, opts, ref.String()), "no signatures found")

	kp, err := loadKeypair(privateKeyPath, nil)
	require.NoError(t, err)

	attach := func(digest, claimed name.Digest) {
		payloadBytes, err := payload.Cosign{Image: claimed}.MarshalJSON()
		require.NoError(t, err)

		sig, _, err := kp.SignData(t.Context(), payloadBytes)
		require.NoError(t, err)

		tag := signatureTag(digest)
		base, err := signatureImage(tag, ropts)
		require.NoError(t, err)

		require.NoError(t, appendSignature(tag, base, payloadBytes, map[string]string{
			signatureAnnotation: base64.StdEncoding.EncodeToString(sig),
		}, ropts))
	}

	// A signature for a different digest must not verify
	attach(digests[0], digests[1])
	require.ErrorContains(t, verifyImage(t, d, opts, ref.String()), "does not match image digest")

	// Appending a valid signature makes the image verify
	attach(digests[0], digests[0])
	require.NoError(t, verifyImage(t, d, opts, ref.String()))

	verifiedDigest, err := d.verifyImage(t.Context(), opts, ref.String())
	require.NoError(t, err)
	require.Equal(t, digests[0].DigestStr(), verifiedDigest)

	sigImage, err := remote.Image(signatureTag(digests[0]), ropts...)
	require.NoError(t, err)

	layers, err := sigImage.Layers()
	require.NoError(t, err)
	require.Len(t, layers, 2)

	// The same payload signed with the same key gets detected
	payloadBytes, err := payload.Cosign{Image: digests[0]}.MarshalJSON()
	require.NoError(t, err)

	existing, err := existingSignature(sigImage, payloadBytes, kp)
	require.NoError(t, err)
	require.NotEmpty(t, existing)

	otherPrivateKeyPath, _ := writeKeyPair(t, nil)
	otherKp, err := loadKeypair(otherPrivateKeyPath, nil)
	require.NoError(t, err)

	existing, err = existingSignature(sigImage, payloadBytes, otherKp)
	require.NoError(t, err)
	require.Empty(t, existing)

	mediaType, err := layers[0].MediaType()
	require.NoError(t, err)
	require.Equal(t, simpleSigningMediaType, mediaType)

	// A different key must not verify
	_, otherPublicKeyPath := writeKeyPair(t, nil)
	otherOpts := *opts
	otherOpts.PublicKeyPath = otherPublicKeyPath
	require.ErrorContains(t, verifyImage(t, d, &otherOpts, ref.String()), "no valid signature found")
}

func verifyImage(t *testing.T, d *defaultImpl, opts *Options, ref string) error {
	t.Helper()

	_, err := d.verifyImage(t.Context(), opts, ref)

	return err
}

func TestIsNotFound(t *testing.T) {
	t.Parallel()

	require.True(t, isNotFound(&transport.Error{
		StatusCode: http.StatusNotFound,
		Errors:     []transport.Diagnostic{{Code: transport.ManifestUnknownErrorCode}},
	}))
	require.False(t, isNotFound(&transport.Error{
		StatusCode: http.StatusNotFound,
		Errors:     []transport.Diagnostic{{Code: transport.NameUnknownErrorCode}},
	}))
	require.False(t, isNotFound(&transport.Error{StatusCode: http.StatusNotFound}))
	require.False(t, isNotFound(errors.New("error")))
}

func TestWriteImageOutputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	opts := &Options{
		OutputSignaturePath:   filepath.Join(dir, "image.sig"),
		OutputCertificatePath: filepath.Join(dir, "image.cert"),
	}

	require.NoError(t, writeImageOutputs(opts, "sig", []byte("cert")))

	content, err := os.ReadFile(opts.OutputSignaturePath)
	require.NoError(t, err)
	require.Equal(t, "sig", string(content))

	content, err = os.ReadFile(opts.OutputCertificatePath)
	require.NoError(t, err)
	require.Equal(t, "cert", string(content))

	require.NoError(t, writeImageOutputs(&Options{}, "sig", nil))
}

func TestPrehashedKeypair(t *testing.T) {
	t.Parallel()

	privateKeyPath, publicKeyPath := writeKeyPair(t, nil)

	kp, err := loadKeypair(privateKeyPath, nil)
	require.NoError(t, err)

	data := []byte("hello kubefolx!")
	digest := sha256.Sum256(data)

	prehashedKp, ok := kp.prehashed(digest[:])
	require.True(t, ok)

	sig, signedDigest, err := prehashedKp.SignData(t.Context(), digest[:])
	require.NoError(t, err)
	require.Equal(t, digest[:], signedDigest)

	b, err := legacyBundle(sig, digest[:], nil, nil)
	require.NoError(t, err)

	d := &defaultImpl{}
	opts := &Options{PublicKeyPath: publicKeyPath}
	require.NoError(t, d.verifyBundle(opts, b, verify.WithArtifact(bytes.NewReader(data)), false))

	// Other data gets hashed before signing
	other := []byte("subject")
	_, otherDigest, err := prehashedKp.SignData(t.Context(), other)
	require.NoError(t, err)

	expected := sha256.Sum256(other)
	require.Equal(t, expected[:], otherDigest)

	// Pure Ed25519 does not support prehashing
	_, ed25519Key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	edKp, err := newKeypair(ed25519Key)
	require.NoError(t, err)

	_, ok = edKp.prehashed(digest[:])
	require.False(t, ok)
}

func TestRekorReadURL(t *testing.T) {
	t.Parallel()

	newImpl := func(rekorLogs ...root.Service) *defaultImpl {
		signingConf, err := root.NewSigningConfig(
			root.SigningConfigMediaType02, nil, nil, rekorLogs,
			root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY}, nil,
			root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY},
		)
		require.NoError(t, err)

		return &defaultImpl{tufClient: &tuf.Client{}, tufFetched: time.Now(), signingConf: signingConf}
	}

	past := time.Now().Add(-24 * time.Hour)

	// An expired v1 instance still gets used for lookups
	d := newImpl(
		root.Service{URL: "https://old.example", MajorAPIVersion: 1, ValidityPeriodStart: past.Add(-time.Hour), ValidityPeriodEnd: past},
		root.Service{URL: "https://expired.example", MajorAPIVersion: 1, ValidityPeriodStart: past, ValidityPeriodEnd: past},
		root.Service{URL: "https://v2.example", MajorAPIVersion: 2, ValidityPeriodStart: past},
	)

	rekorURL, err := d.rekorReadURL()
	require.NoError(t, err)
	require.Equal(t, "https://expired.example", rekorURL)

	_, err = d.rekorService()
	require.ErrorContains(t, err, "legacy signatures require Rekor v1")

	// Fall back to the public instance without any v1 instance
	d = newImpl(root.Service{URL: "https://v2.example", MajorAPIVersion: 2, ValidityPeriodStart: past})

	rekorURL, err = d.rekorReadURL()
	require.NoError(t, err)
	require.Equal(t, defaultRekorURL, rekorURL)
}

func TestTUFOptions(t *testing.T) {
	const mirror = "https://tuf.example"

	rootJSON := []byte(`{"signed":{}}`)

	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, cacheDir string)
		mirror  string
		root    []byte
		err     string
	}{
		{
			name:   "default",
			mirror: tuf.DefaultMirror,
			root:   tuf.DefaultOptions().Root,
		},
		{
			name: "mirror without root",
			prepare: func(t *testing.T, _ string) {
				t.Helper()
				t.Setenv(tufMirrorEnv, mirror)
			},
			err: "read TUF root for mirror " + mirror,
		},
		{
			name: "mirror with root JSON",
			prepare: func(t *testing.T, cacheDir string) {
				t.Helper()

				rootPath := filepath.Join(cacheDir, "custom-root.json")
				require.NoError(t, os.WriteFile(rootPath, rootJSON, 0o600))
				t.Setenv(tufMirrorEnv, mirror)
				t.Setenv(tufRootJSONEnv, rootPath)
			},
			mirror: mirror,
			root:   rootJSON,
		},
		{
			name: "cosign initialize",
			prepare: func(t *testing.T, cacheDir string) {
				t.Helper()

				require.NoError(t, os.WriteFile(
					filepath.Join(cacheDir, "remote.json"), []byte(`{"mirror":"`+mirror+`"}`), 0o600,
				))

				rootDir := filepath.Join(cacheDir, tuf.URLToPath(mirror))
				require.NoError(t, os.MkdirAll(rootDir, 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(rootDir, "root.json"), rootJSON, 0o600))
			},
			mirror: mirror,
			root:   rootJSON,
		},
		{
			name: "invalid remote.json",
			prepare: func(t *testing.T, cacheDir string) {
				t.Helper()
				require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "remote.json"), []byte("{"), 0o600))
			},
			err: "unmarshal remote.json",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			t.Setenv(tufRootEnv, cacheDir)
			t.Setenv(tufMirrorEnv, "")
			t.Setenv(tufRootJSONEnv, "")

			if tc.prepare != nil {
				tc.prepare(t, cacheDir)
			}

			opts, err := tufOptions()
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, cacheDir, opts.CachePath)
			require.Equal(t, tc.mirror, opts.RepositoryBaseURL)
			require.Equal(t, tc.root, opts.Root)
		})
	}
}

func TestSignatureImageNotFound(t *testing.T) {
	t.Parallel()

	status := http.StatusNotFound

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			return
		}

		// No error body, like some registries do for missing tags
		w.WriteHeader(status)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	tag, err := name.NewTag(u.Host + "/test:sha256-abc.sig")
	require.NoError(t, err)

	img, err := signatureImage(tag, nil)
	require.NoError(t, err)

	manifest, err := img.Manifest()
	require.NoError(t, err)
	require.Empty(t, manifest.Layers)

	status = http.StatusForbidden
	_, err = signatureImage(tag, nil)
	require.ErrorContains(t, err, "get signature image")
}

func TestVerifyImageWithoutHead(t *testing.T) {
	t.Parallel()

	reg := registry.New()
	allowHead := true

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowHead && r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/") {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		reg.ServeHTTP(w, r)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	img, err := random.Image(64, 1)
	require.NoError(t, err)

	ref, err := name.ParseReference(u.Host + "/test:latest")
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, img))

	allowHead = false

	_, publicKeyPath := writeKeyPair(t, nil)
	opts := &Options{PublicKeyPath: publicKeyPath, IgnoreTlog: true}

	require.ErrorContains(t, verifyImage(t, &defaultImpl{}, opts, ref.String()), "no signatures found")
}
