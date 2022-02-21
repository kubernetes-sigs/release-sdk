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
	"testing"

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
		prepare func(*signfakes.FakeImpl)
		assert  func(*sign.SignedObject, error)
	}{
		{ // Success
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
			},
		},
		{ // Success with failed unset experimental
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
		tc.prepare(mock)

		opts := sign.Default()
		opts.Verbose = true

		sut := sign.New(opts)
		sut.SetImpl(mock)

		obj, err := sut.SignImage("gcr.io/fake/honk:99.99.99")
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
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, err)
				require.Nil(t, obj)
			},
		},
		{ // Failure on set experimental
			prepare: func(mock *signfakes.FakeImpl) {
				mock.SetenvReturns(errTest)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, err)
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
