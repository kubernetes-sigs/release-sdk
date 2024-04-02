/*
Copyright 2022 The Kubernetes Authors.

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

package sign_test

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-sdk/sign"
	"sigs.k8s.io/release-sdk/sign/signfakes"
)

var errTest = errors.New("error")

func TestUploadBlob(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*signfakes.FakeImpl)
		assert  func(error)
	}{
		{ // Success
			prepare: func(mock *signfakes.FakeImpl) {
			},
			assert: func(err error) {
				require.Nil(t, err)
			},
		},
	} {
		mock := &signfakes.FakeImpl{}
		tc.prepare(mock)

		sut := sign.New(sign.Default())
		sut.SetImpl(mock)

		err := sut.UploadBlob("")
		tc.assert(err)
	}
}

func TestSignImage(t *testing.T) {
	t.Parallel()
	// Some of these tests require a real IDentity token
	token := "DUMMYTOKEN"

	for _, tc := range []struct {
		fakeReference *FakeReferenceStub
		prepare       func(*signfakes.FakeImpl)
		assert        func(*sign.SignedObject, error)
	}{
		{ // Success
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyImageInternalReturns(&sign.SignedObject{}, nil)
				mock.SignImageInternalReturns(nil)
				mock.TokenFromProvidersReturns(token, nil)
				m := &sync.Map{}
				m.Store("gcr.io/fake/honk:99.99.99", &sign.SignedObject{})
				mock.ImagesSignedReturns(m, nil)
				mock.DigestReturns("sha256:honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a", nil)
				mock.NewWithContextReturns(&testRoundTripper{}, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NoError(t, err)
				require.NotNil(t, obj)
				require.NotEmpty(t, obj.Image().Reference())
				require.NotEmpty(t, obj.Image().Digest())
				require.NotEmpty(t, obj.Image().Signature())
				require.Equal(t, obj.Image().Reference(), "gcr.io/fake/honk:99.99.99")
				require.Equal(t, obj.Image().Digest(), "sha256:honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a")
				require.Equal(t, obj.Image().Signature(), "gcr.io/fake/honk:sha256-honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a.sig")
			},
		},
		{ // Failure on Verify
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				m := &sync.Map{}
				m.Store("gcr.io/fake/honk:99.99.99", true)
				mock.ImagesSignedReturns(nil, errTest)
				mock.VerifyImageInternalReturns(nil, errTest)
				mock.SignImageInternalReturns(nil)
				mock.TokenFromProvidersReturns(token, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Error(t, err)
				require.Nil(t, obj)
			},
		},
		{ // Failure on Sign
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyImageInternalReturns(&sign.SignedObject{}, nil)
				mock.SignImageInternalReturns(errTest)
				mock.TokenFromProvidersReturns(token, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Error(t, err)
				require.Nil(t, obj)
			},
		},
		{ // Failure getting identity token
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				mock.TokenFromProvidersReturns(token, errTest)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Error(t, err)
				require.Nil(t, obj)
			},
		},
	} {
		mock := &signfakes.FakeImpl{}
		mock.ParseReferenceReturns(tc.fakeReference, nil)
		tc.prepare(mock)

		opts := sign.Default()
		opts.Verbose = true

		sut := sign.New(opts)
		sut.SetImpl(mock)

		obj, err := sut.SignImage(tc.fakeReference.image)
		tc.assert(obj, err)
	}
}

func TestSignFile(t *testing.T) {
	t.Parallel()

	opts := sign.Default()
	opts.PrivateKeyPath = "/dummy/cosign.key"
	opts.PublicKeyPath = "/dummy/cosign.pub"

	// Create temporary directory for files.
	tempDir, err := os.MkdirTemp("", "k8s-test-file-")
	require.Nil(t, err)
	defer func() {
		require.Nil(t, os.RemoveAll(tempDir))
	}()

	// Create temporary file for test.
	tempFile := filepath.Join(tempDir, "test-file")
	require.Nil(t, os.WriteFile(tempFile, []byte("dummy-content"), 0o644))

	for _, tc := range []struct {
		path    string
		options *sign.Options
		prepare func(*signfakes.FakeImpl)
		assert  func(*sign.SignedObject, error)
	}{
		{ // Success
			path:    tempFile,
			options: opts,
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyFileInternalReturns(nil)
				mock.SignFileInternalReturns(nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, err)
				require.NotNil(t, obj)
				require.NotEmpty(t, obj.File().Path())
				require.NotEmpty(t, obj.File().CertificatePath())
				require.NotEmpty(t, obj.File().SignaturePath())
			},
		},
		{ // Success custom sig and cert.
			path: tempFile,
			options: &sign.Options{
				PrivateKeyPath:        opts.PrivateKeyPath,
				OutputSignaturePath:   "/tmp/test-file.sig",
				OutputCertificatePath: "/tmp/test-file.cert",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyFileInternalReturns(nil)
				mock.SignFileInternalReturns(nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, err)
				require.NotNil(t, obj)
				require.NotEmpty(t, obj.File().Path())
				require.NotEmpty(t, obj.File().CertificatePath())
				require.NotEmpty(t, obj.File().SignaturePath())
			},
		},
		{ // File does not exist.
			path:    "/dummy/test-no-file",
			options: opts,
			prepare: func(mock *signfakes.FakeImpl) {
				mock.PayloadBytesReturns(nil, errTest)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, obj)
				require.ErrorContains(t, err, "file retrieve sha256:")
			},
		},
		{ // File does can't sign.
			path:    tempFile,
			options: opts,
			prepare: func(mock *signfakes.FakeImpl) {
				mock.SignFileInternalReturns(errTest)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, obj)
				require.ErrorContains(t, err, "sign file:")
			},
		},
		{ // Default sig and cert file test
			path:    tempFile,
			options: opts,
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyFileInternalReturns(nil)
				mock.SignFileInternalReturns(nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, err)

				require.NotNil(t, obj)
				require.NotEmpty(t, obj.File().Path())
				require.NotEmpty(t, obj.File().CertificatePath())
				require.NotEmpty(t, obj.File().SignaturePath())

				require.Equal(t, obj.File().Path()+".cert", obj.File().CertificatePath())
				require.Equal(t, obj.File().Path()+".sig", obj.File().SignaturePath())
			},
		},
		{ // Verify failed.
			path:    tempFile,
			options: opts,
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyFileInternalReturns(errTest)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, obj)
				require.NotNil(t, err)
				require.ErrorContains(t, err, "verifying signed file:")
			},
		},
	} {
		mock := &signfakes.FakeImpl{}
		tc.prepare(mock)

		opts := tc.options
		opts.Verbose = true

		sut := sign.New(opts)
		sut.SetImpl(mock)

		obj, err := sut.SignFile(tc.path)
		tc.assert(obj, err)
	}
}

func TestVerifyImage(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		fakeReference *FakeReferenceStub
		prepare       func(*signfakes.FakeImpl)
		assert        func(*sign.SignedObject, error)
	}{
		{ // Success
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyImageInternalReturns(&sign.SignedObject{}, nil)
				m := &sync.Map{}
				m.Store("gcr.io/fake/honk:99.99.99", true)
				mock.ImagesSignedReturns(m, nil)
				mock.DigestReturns("sha256:honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a", nil)
				mock.NewWithContextReturns(&testRoundTripper{}, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, err)
			},
		},
		{ // Failure on Verify
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyImageInternalReturns(nil, errTest)
				mock.SetenvReturns(nil)
				mock.ImagesSignedReturns(nil, errTest)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, err)
				require.Nil(t, obj)
			},
		},
		{ // Skip on no signatures listed
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				m := &sync.Map{}
				m.Store("gcr.io/fake/honk:99.99.99", false)
				mock.ImagesSignedReturns(m, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, err)
				require.NotNil(t, obj)
			},
		},
	} {
		mock := &signfakes.FakeImpl{}
		mock.ParseReferenceReturns(tc.fakeReference, nil)
		tc.prepare(mock)

		sut := sign.New(sign.Default())
		sut.SetImpl(mock)

		obj, err := sut.VerifyImage(tc.fakeReference.image)
		tc.assert(obj, err)
	}
}

func TestVerifyFile(t *testing.T) {
	t.Parallel()

	// Create temporary directory for files.
	tempDir, err := os.MkdirTemp("", "k8s-test-file-")
	require.Nil(t, err)
	defer func() {
		require.Nil(t, os.RemoveAll(tempDir))
	}()

	// Create temporary file for test.
	tempFile := filepath.Join(tempDir, "test-file")

	payload := []byte("honk")
	payloadSha256 := "4de18cc93efe15c1d1cc2407cfc9f054b4d9217975538ac005dba541acee1954"
	uuid := "uuid"
	var logindex int64 = 1
	uuids := []models.LogEntryAnon{
		{
			LogID:    &uuid,
			LogIndex: &logindex,
		},
	}
	require.Nil(t, os.WriteFile(tempFile, payload, 0o644))

	for _, tc := range []struct {
		path    string
		options *sign.Options
		prepare func(*signfakes.FakeImpl)
		assert  func(*sign.SignedObject, error)
	}{
		{ // Success
			path:    tempFile,
			options: sign.Default(),
			prepare: func(mock *signfakes.FakeImpl) {
				mock.PayloadBytesReturns(payload, nil)
				mock.FindTlogEntryReturns(uuids, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, obj.File)
				require.Equal(t, obj.File().Path(), tempFile)
				require.Equal(t, obj.File().SHA256(), payloadSha256)
				require.Nil(t, err)
			},
		},
		{ // File not signed
			path:    tempFile,
			options: sign.Default(),
			prepare: func(mock *signfakes.FakeImpl) {
				mock.PayloadBytesReturns(nil, nil)
				mock.FindTlogEntryReturns(nil, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, obj)
				require.Nil(t, err)
			},
		},
		{ // File tlog not found
			path:    tempFile,
			options: sign.Default(),
			prepare: func(mock *signfakes.FakeImpl) {
				mock.PayloadBytesReturns(payload, nil)
				mock.FindTlogEntryReturns(uuids, nil)
				mock.VerifyFileInternalReturns(errTest)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, obj)
				require.NotNil(t, err)
				require.ErrorContains(t, err, "verify file reference")
			},
		},
		{ // File tlog error
			path:    tempFile,
			options: sign.Default(),
			prepare: func(mock *signfakes.FakeImpl) {
				mock.PayloadBytesReturns(payload, nil)
				mock.FindTlogEntryReturns(nil, errTest)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, obj)
				require.NotNil(t, err)
				require.ErrorContains(t, err, "find rekor tlog entries")
			},
		},
	} {
		mock := &signfakes.FakeImpl{}
		tc.prepare(mock)

		tmpDir := t.TempDir()
		_, pubFile := generateKeyFile(t, tmpDir, nil)
		opts := tc.options
		opts.Verbose = true
		opts.PublicKeyPath = pubFile

		sut := sign.New(opts)
		sut.SetImpl(mock)

		obj, err := sut.VerifyFile(tc.path, false)
		tc.assert(obj, err)
	}
}

func generateKeyFile(t *testing.T, tmpDir string, pf cosign.PassFunc) (privFile, pubFile string) {
	t.Helper()

	tmpPrivFile, err := os.CreateTemp(tmpDir, "cosign_test_*.key")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer tmpPrivFile.Close()
	tmpPubFile, err := os.CreateTemp(tmpDir, "cosign_test_*.pub")
	if err != nil {
		t.Fatalf("failed to create temp pub file: %v", err)
	}
	defer tmpPubFile.Close()

	// Generate a valid keypair.
	keys, err := cosign.GenerateKeyPair(pf)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	if _, err := tmpPrivFile.Write(keys.PrivateBytes); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	if _, err := tmpPubFile.Write(keys.PublicBytes); err != nil {
		t.Fatalf("failed to write pub file: %v", err)
	}
	return tmpPrivFile.Name(), tmpPubFile.Name()
}

func TestIsImageSigned(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*signfakes.FakeImpl)
		assert  func(bool, error)
	}{
		{ // Success, signed
			prepare: func(mock *signfakes.FakeImpl) {
				m := &sync.Map{}
				m.Store("", true)
				mock.ImagesSignedReturns(m, nil)
			},
			assert: func(signed bool, err error) {
				require.True(t, signed)
				require.Nil(t, err)
			},
		},
		{ // Success, not signed
			prepare: func(mock *signfakes.FakeImpl) {
				m := &sync.Map{}
				m.Store("", false)
				mock.ImagesSignedReturns(m, nil)
			},
			assert: func(signed bool, err error) {
				require.False(t, signed)
				require.Nil(t, err)
			},
		},
		{ // failure ImagesSigned errors
			prepare: func(mock *signfakes.FakeImpl) {
				mock.ImagesSignedReturns(nil, errTest)
			},
			assert: func(signed bool, err error) {
				require.Error(t, err)
			},
		},
		{ // failure ref not part of the result
			prepare: func(mock *signfakes.FakeImpl) {
				m := &sync.Map{}
				mock.ImagesSignedReturns(m, nil)
			},
			assert: func(signed bool, err error) {
				require.Error(t, err)
			},
		},
		{ // failure on interface conversion
			prepare: func(mock *signfakes.FakeImpl) {
				m := &sync.Map{}
				m.Store("", 1)
				mock.ImagesSignedReturns(m, nil)
			},
			assert: func(signed bool, err error) {
				require.Error(t, err)
			},
		},
	} {
		mock := &signfakes.FakeImpl{}
		tc.prepare(mock)

		sut := sign.New(sign.Default())
		sut.SetImpl(mock)

		res, err := sut.IsImageSigned("")
		tc.assert(res, err)
	}
}

// FakeReferenceStub implements the name.Reference to we use in the testing
//
//	type FakeReferenceStub interface {
//		fmt.Stringer
//		// Context accesses the Repository context of the reference.
//		Context() name.Repository
//		// Identifier accesses the type-specific portion of the reference.
//		Identifier() string
//		// Name is the fully-qualified reference name.
//		Name() string
//		// Scope is the scope needed to access this reference.
//		Scope(string)
//	}
type FakeReferenceStub struct {
	image      string
	registry   string
	repository string
}

func (fr *FakeReferenceStub) Context() name.Repository {
	reg, err := name.NewRepository(fr.repository, name.WithDefaultRegistry(fr.registry))
	if err != nil {
		log.Fatal(err)
	}
	return reg
}

func (*FakeReferenceStub) Identifier() string {
	return ""
}

func (*FakeReferenceStub) Scope(s string) string {
	return s
}

func (fr *FakeReferenceStub) Name() string {
	return fr.image
}

func (fr *FakeReferenceStub) String() string {
	return fr.image
}

type testRoundTripper struct{}

func (t *testRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, nil
}

func TestImagesSigned(t *testing.T) {
	t.Parallel()

	fakeRef := &FakeReferenceStub{
		image:      "gcr.io/fake/honk:99.99.99",
		registry:   "gcr.io",
		repository: "fake/honk",
	}

	for _, tc := range []struct {
		prepare func(*signfakes.FakeImpl)
		assert  func(*sync.Map, error)
	}{
		{ // Success, signed
			prepare: func(mock *signfakes.FakeImpl) {
				mock.ParseReferenceReturns(fakeRef, nil)
				mock.NewWithContextReturns(&testRoundTripper{}, nil)
			},
			assert: func(res *sync.Map, err error) {
				require.Nil(t, err)

				signed, ok := res.Load("")
				require.True(t, ok)
				require.True(t, signed.(bool))
			},
		},
		{ // Success, unsigned
			prepare: func(mock *signfakes.FakeImpl) {
				mock.ParseReferenceReturns(fakeRef, nil)
				mock.NewWithContextReturns(&testRoundTripper{}, nil)
				mock.DigestReturnsOnCall(1, "", &transport.Error{
					Errors: []transport.Diagnostic{
						{Code: transport.ManifestUnknownErrorCode},
					},
				})
			},
			assert: func(res *sync.Map, err error) {
				require.Nil(t, err)

				signed, ok := res.Load("")
				require.True(t, ok)
				require.False(t, signed.(bool))
			},
		},
		{ // failure on ParseReference
			prepare: func(mock *signfakes.FakeImpl) {
				mock.ParseReferenceReturns(nil, errTest)
			},
			assert: func(res *sync.Map, err error) {
				require.NotNil(t, err)
				require.Nil(t, res)
			},
		},
		{ // failure on NewWithContext
			prepare: func(mock *signfakes.FakeImpl) {
				mock.ParseReferenceReturns(fakeRef, nil)
				mock.NewWithContextReturns(nil, errTest)
			},
			assert: func(res *sync.Map, err error) {
				require.NotNil(t, err)
				require.Nil(t, res)
			},
		},
		{ // failure on first Digest
			prepare: func(mock *signfakes.FakeImpl) {
				mock.ParseReferenceReturns(fakeRef, nil)
				mock.NewWithContextReturns(&testRoundTripper{}, nil)
				mock.DigestReturns("", errTest)
			},
			assert: func(res *sync.Map, err error) {
				require.NotNil(t, err)
				require.NotNil(t, res) // partial results are possible
			},
		},
		{ // failure on second Digest
			prepare: func(mock *signfakes.FakeImpl) {
				mock.ParseReferenceReturns(fakeRef, nil)
				mock.NewWithContextReturns(&testRoundTripper{}, nil)
				mock.DigestReturnsOnCall(1, "", errTest)
			},
			assert: func(res *sync.Map, err error) {
				require.NotNil(t, err)
				require.NotNil(t, res) // partial results are possible
			},
		},
	} {
		mock := &signfakes.FakeImpl{}
		tc.prepare(mock)

		sut := sign.New(sign.Default())
		sut.SetImpl(mock)

		res, err := sut.ImagesSigned(context.TODO(), "")
		tc.assert(res, err)
	}
}
