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

// nolint: dupl
func TestSignImage(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*signfakes.FakeImpl)
		assert  func(*sign.SignedObject, error)
	}{
		{ // Success
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyInternalReturns(&sign.SignedObject{}, nil)
				mock.SignImageInternalReturns(nil)
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
				mock.VerifyInternalReturns(nil, errTest)
				mock.SignImageInternalReturns(nil)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, err)
				require.Nil(t, obj)
			},
		},
		{ // Failure on Sign
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyInternalReturns(&sign.SignedObject{}, nil)
				mock.SignImageInternalReturns(errTest)
			},
			assert: func(obj *sign.SignedObject, err error) {
				require.NotNil(t, err)
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

// nolint: dupl
func TestSignFile(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*signfakes.FakeImpl)
		assert  func(*sign.SignedObject, error)
	}{
		{ // Success
			prepare: func(mock *signfakes.FakeImpl) {
				mock.VerifyInternalReturns(&sign.SignedObject{}, nil)
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
				mock.VerifyInternalReturns(nil, errTest)
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

func TestVerify(t *testing.T) {
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

		obj, err := sut.Verify("")
		tc.assert(obj, err)
	}
}
