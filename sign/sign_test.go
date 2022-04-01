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
		attachSignature bool
		fakeReference   *FakeReferenceStub
		prepare         func(*signfakes.FakeImpl)
		assert          func(*sign.SignedObject, error)
	}{
		{ // Success
			attachSignature: false,
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyImageInternalReturns(&sign.SignedObject{}, nil)
				mock.SignImageInternalReturns(nil)
				mock.TokenFromProvidersReturns(token, nil)
				mock.DigestReturns("sha256:honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a", nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NoError(t, err)
				require.NotNil(t, obj)
				require.NotEmpty(t, obj.Reference())
				require.NotEmpty(t, obj.Digest())
				require.NotEmpty(t, obj.Signature())
				require.Equal(t, obj.Reference(), "gcr.io/fake/honk:99.99.99")
				require.Equal(t, obj.Digest(), "sha256:honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a")
				require.Equal(t, obj.Signature(), "gcr.io/fake/honk:sha256-honk69059c8e84bed02f4c4385d432808e2c8055eb5087f7fea74e286b736a.sig")
			},
		},
		{ // Success
			attachSignature: true,
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyImageInternalReturns(&sign.SignedObject{}, nil)
				mock.SignImageInternalReturns(nil)
				mock.TokenFromProvidersReturns(token, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NoError(t, err)
				require.NotNil(t, obj)
				require.Empty(t, obj.Reference())
				require.Empty(t, obj.Digest())
				require.Empty(t, obj.Signature())
			},
		},
		{ // Success with failed unset experimental
			attachSignature: true,
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyImageInternalReturns(&sign.SignedObject{}, nil)
				mock.SetenvReturnsOnCall(1, errTest)
				mock.TokenFromProvidersReturns(token, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, obj)
				require.Empty(t, obj.Reference())
				require.Empty(t, obj.Digest())
				require.NoError(t, err)
			},
		},
		{ // Failure on Verify
			attachSignature: true,
			fakeReference: &FakeReferenceStub{
				image:      "gcr.io/fake/honk:99.99.99",
				registry:   "gcr.io",
				repository: "fake/honk",
			},
			prepare: func(mock *signfakes.FakeImpl) {
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
			attachSignature: true,
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
			attachSignature: true,
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
			attachSignature: true,
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
		opts.AttachSignature = tc.attachSignature

		sut := sign.New(opts)
		sut.SetImpl(mock)

		obj, err := sut.SignImage(tc.fakeReference.image)
		tc.assert(obj, err)
	}
}

func TestSignFile(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*signfakes.FakeImpl)
		assert  func(*sign.SignedObject, error)
	}{
		{ // Success
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyFileInternalReturns(&sign.SignedObject{}, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, obj)
				require.Empty(t, obj.Reference())
				require.Empty(t, obj.Digest())
				require.Nil(t, err)
			},
		},
		{ // Failure on Verify
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyFileInternalReturns(nil, errTest)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, err)
				require.Nil(t, obj)
			},
		},
	} {
		mock := &signfakes.FakeImpl{}
		tc.prepare(mock)

		sut := sign.New(&sign.Options{Verbose: true})
		sut.SetImpl(mock)

		obj, err := sut.SignFile("")
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
		prepare func(*signfakes.FakeImpl)
		assert  func(*sign.SignedObject, error)
	}{
		{ // Success
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyImageInternalReturns(&sign.SignedObject{}, nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, err)
			},
		},
		{ // Success with failed unset experimental
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyImageInternalReturns(&sign.SignedObject{}, nil)
				mock.SetenvReturnsOnCall(1, errTest)
				prepareSignatureList(t, mock)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, obj)
				require.Empty(t, obj.Reference())
				require.Empty(t, obj.Digest())
				require.Nil(t, err)
			},
		},
		{ // Failure on Verify
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
		tc.prepare(mock)

		sut := sign.New(sign.Default())
		sut.SetImpl(mock)

		obj, err := sut.VerifyImage("gcr.io/fake/honk:99.99.99")
		tc.assert(obj, err)
	}
}

func TestVerifyFile(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*signfakes.FakeImpl)
		assert  func(*sign.SignedObject, error)
	}{
		{ // Success
			prepare: func(mock *signfakes.FakeImpl) {
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.Nil(t, err)
			},
		},
	} {
		mock := &signfakes.FakeImpl{}
		tc.prepare(mock)

		sut := sign.New(sign.Default())
		sut.SetImpl(mock)

		obj, err := sut.VerifyFile("")
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
