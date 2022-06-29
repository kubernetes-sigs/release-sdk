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
	"errors"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/static"
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
				sig, err := static.NewSignature([]byte{}, "honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a")
				require.Nil(t, err)

				mock.SignaturesListReturns([]oci.Signature{sig}, nil)
				mock.DigestReturns("sha256:honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a", nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NoError(t, err)
				require.NotNil(t, obj)
				require.NotEmpty(t, obj.Image.Reference())
				require.NotEmpty(t, obj.Image.Digest())
				require.NotEmpty(t, obj.Image.Signature())
				require.Equal(t, obj.Image.Reference(), "gcr.io/fake/honk:99.99.99")
				require.Equal(t, obj.Image.Digest(), "sha256:honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a")
				require.Equal(t, obj.Image.Signature(), "gcr.io/fake/honk:sha256-honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a.sig")
			},
		},
		{ // Success with failed unset experimental
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				sig, err := static.NewSignature([]byte{}, "honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a")
				require.Nil(t, err)

				mock.SignaturesListReturns([]oci.Signature{sig}, nil)
				mock.VerifyImageInternalReturns(&sign.SignedObject{}, nil)
				mock.SetenvReturnsOnCall(2, errTest)
				mock.TokenFromProvidersReturns(token, nil)
				mock.DigestReturns("sha256:honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a", nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NoError(t, err)
				require.NotNil(t, obj)
				require.NotEmpty(t, obj.Image.Reference())
				require.NotEmpty(t, obj.Image.Digest())
				require.NotEmpty(t, obj.Image.Signature())
				require.Equal(t, obj.Image.Reference(), "gcr.io/fake/honk:99.99.99")
				require.Equal(t, obj.Image.Digest(), "sha256:honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a")
				require.Equal(t, obj.Image.Signature(), "gcr.io/fake/honk:sha256-honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a.sig")
			},
		},
		{ // Failure on Verify
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				sig, err := static.NewSignature([]byte{}, "honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a")
				require.Nil(t, err)

				mock.SignaturesListReturns([]oci.Signature{sig}, nil)
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
		{ // Failure on set experimental
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				mock.SetenvReturns(errTest)
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
				require.NotEmpty(t, obj.File.Path())
				require.NotEmpty(t, obj.File.CertificatePath())
				require.NotEmpty(t, obj.File.SignaturePath())
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
				require.NotEmpty(t, obj.File.Path())
				require.NotEmpty(t, obj.File.CertificatePath())
				require.NotEmpty(t, obj.File.SignaturePath())
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
				require.NotEmpty(t, obj.File.Path())
				require.NotEmpty(t, obj.File.CertificatePath())
				require.NotEmpty(t, obj.File.SignaturePath())

				require.Equal(t, obj.File.Path()+".cert", obj.File.CertificatePath())
				require.Equal(t, obj.File.Path()+".sig", obj.File.SignaturePath())
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

func prepareSignatureList(t *testing.T, mock *signfakes.FakeImpl) {
	sig, err := static.NewSignature([]byte{}, "s1")
	require.Nil(t, err)

	mock.SignaturesListReturns([]oci.Signature{sig}, nil)
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
				mock.DigestReturns("sha256:honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a", nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, err)
			},
		},
		{ // Success with failed unset experimental
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyImageInternalReturns(&sign.SignedObject{}, nil)
				mock.SetenvReturnsOnCall(1, errTest)
				prepareSignatureList(t, mock)
				mock.DigestReturns("sha256:honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a", nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, obj)
				require.NotEmpty(t, obj.Image.Reference())
				require.NotEmpty(t, obj.Image.Digest())
				require.NotEmpty(t, obj.Image.Signature())
				require.Equal(t, obj.Image.Reference(), "gcr.io/fake/honk:99.99.99")
				require.Equal(t, obj.Image.Digest(), "sha256:honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a")
				require.Equal(t, obj.Image.Signature(), "gcr.io/fake/honk:sha256-honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a.sig")
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
				prepareSignatureList(t, mock)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, err)
				require.Nil(t, obj)
			},
		},
		{ // Failure on set experimental
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				prepareSignatureList(t, mock)
				mock.SetenvReturns(errTest)
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
				mock.SignaturesListReturns([]oci.Signature{}, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, err)
				require.Nil(t, obj)
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
	uuids := []string{
		"uuid",
	}
	require.Nil(t, os.WriteFile(tempFile, []byte(payload), 0o644))

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
				mock.FindTLogEntriesByPayloadReturns(uuids, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, obj.File)
				require.Equal(t, obj.File.Path(), tempFile)
				require.Equal(t, obj.File.SHA256(), payloadSha256)
				require.Nil(t, err)
			},
		},
		{ // File not signed
			path:    tempFile,
			options: sign.Default(),
			prepare: func(mock *signfakes.FakeImpl) {
				mock.PayloadBytesReturns(nil, nil)
				mock.FindTLogEntriesByPayloadReturns(nil, nil)
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
				mock.FindTLogEntriesByPayloadReturns(uuids, nil)
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
				mock.FindTLogEntriesByPayloadReturns(nil, errTest)
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

		opts := tc.options
		opts.Verbose = true

		sut := sign.New(opts)
		sut.SetImpl(mock)

		obj, err := sut.VerifyFile(tc.path)
		tc.assert(obj, err)
	}
}

func TestIsImageSigned(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*signfakes.FakeImpl)
		assert  func(bool, error)
	}{
		{ // Success, signed
			prepare: func(mock *signfakes.FakeImpl) {
				sig, err := static.NewSignature([]byte{}, "s1")
				require.Nil(t, err)

				mock.SignaturesListReturns([]oci.Signature{sig}, nil)
			},
			assert: func(signed bool, err error) {
				require.True(t, signed)
				require.Nil(t, err)
			},
		},
		{ // Success, not signed
			prepare: func(mock *signfakes.FakeImpl) {},
			assert: func(signed bool, err error) {
				require.False(t, signed)
				require.Nil(t, err)
			},
		},
		{ // failure SignaturesList errors
			prepare: func(mock *signfakes.FakeImpl) {
				mock.SignaturesListReturns(nil, errTest)
			},
			assert: func(signed bool, err error) {
				require.Error(t, err)
			},
		},
		{ // failure Signatures errors
			prepare: func(mock *signfakes.FakeImpl) {
				mock.SignaturesReturns(nil, errTest)
			},
			assert: func(signed bool, err error) {
				require.Error(t, err)
			},
		},
		{ // failure SignedEntity errors
			prepare: func(mock *signfakes.FakeImpl) {
				mock.SignedEntityReturns(nil, errTest)
			},
			assert: func(signed bool, err error) {
				require.Error(t, err)
			},
		},
		{ // failure ParseReference errors
			prepare: func(mock *signfakes.FakeImpl) {
				mock.ParseReferenceReturns(nil, errTest)
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
// type FakeReferenceStub interface {
// 	fmt.Stringer
// 	// Context accesses the Repository context of the reference.
// 	Context() name.Repository
// 	// Identifier accesses the type-specific portion of the reference.
// 	Identifier() string
// 	// Name is the fully-qualified reference name.
// 	Name() string
// 	// Scope is the scope needed to access this reference.
// 	Scope(string)
// }
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
