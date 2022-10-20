//go:build integration
// +build integration

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

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/release-sdk/sign"
)

const (
	testFile = "hello kubefolx!"
)

type cleanupFn func() error

func generateCosignKeyPair(t *testing.T) (privateKeyPath, publicKeyPath string, fn cleanupFn) {
	tempDir, err := os.MkdirTemp("", "k8s-cosign-keys-")
	require.Nil(t, err)

	keys, err := cosign.GenerateKeyPair(nil)
	require.Nil(t, err)
	require.NotNil(t, keys)

	privateKeyPath = filepath.Join(tempDir, "cosign.key")
	err = os.WriteFile(privateKeyPath, keys.PrivateBytes, 0o600)
	require.Nil(t, err)

	publicKeyPath = filepath.Join(tempDir, "cosign.pub")
	err = os.WriteFile(publicKeyPath, keys.PublicBytes, 0o644)
	require.Nil(t, err)
	cleanupFn := func() error {
		return os.RemoveAll(tempDir)
	}
	return privateKeyPath, publicKeyPath, cleanupFn
}

func TestSuccessSignImage(t *testing.T) {
	imageName := fmt.Sprintf("localhost:5000/honk:%d", time.Now().Unix())
	reg := runDockerRegistryWithDummyImage(t, imageName)
	defer deleteRegistryContainer(t)

	privateKeyPath, publicKeyPath, cleanup := generateCosignKeyPair(t)
	defer func() {
		require.Nil(t, cleanup())
	}()

	opts := sign.Default()
	opts.PrivateKeyPath = privateKeyPath
	opts.PublicKeyPath = publicKeyPath

	signer := sign.New(opts)

	signedObject, err := signer.SignImage(reg.ImageName)
	require.Nil(t, err)
	require.NotNil(t, signedObject)
	verifiedObject, err := signer.VerifyImage(reg.ImageName)
	require.Nil(t, err)
	require.NotNil(t, verifiedObject)
}

func TestSuccessSignFile(t *testing.T) {
	// Setup the temp dir
	tempDir, err := os.MkdirTemp("", "k8s-test-file-")
	require.Nil(t, err)
	defer func() {
		require.Nil(t, os.RemoveAll(tempDir))
	}()

	// Write the test file
	testFilePath := filepath.Join(tempDir, "test")
	testFileCertPath := filepath.Join(tempDir, "test.cert")
	testFileSigPath := filepath.Join(tempDir, "test.sig")
	require.Nil(t, os.WriteFile(testFilePath, []byte(testFile), 0o644))

	privateKeyPath, publicKeyPath, cleanup := generateCosignKeyPair(t)
	defer func() {
		require.Nil(t, cleanup())
	}()

	opts := sign.Default()
	opts.PrivateKeyPath = privateKeyPath
	opts.PublicKeyPath = publicKeyPath
	opts.OutputCertificatePath = testFileCertPath
	opts.OutputSignaturePath = testFileSigPath

	signer := sign.New(opts)

	signedObject, err := signer.SignFile(testFilePath)
	require.Nil(t, err)
	require.NotNil(t, signedObject.File)

	verifiedObject, err := signer.VerifyFile(testFilePath)
	require.Nil(t, err)
	require.NotNil(t, verifiedObject.File)
}

func TestIsImageSigned(t *testing.T) {
	signer := sign.New(sign.Default())
	for _, tc := range []struct {
		imageRef  string
		isSigned  bool
		shouldErr bool
	}{
		{
			// cosign ~1.5.2 signed image
			"ghcr.io/sigstore/cosign/cosign:f436d7637caaa9073522ae65a8416e38cd69c4f2", true, false,
		},
		{
			// k8s/pause ~feb 13 2022. not signed
			"k8s.gcr.io/pause@sha256:a78c2d6208eff9b672de43f880093100050983047b7b0afe0217d3656e1b0d5f", false, false,
		},
		{
			// nonexistent image, must fail
			"kornotios/supermegafakeimage", false, true,
		},
	} {
		res, err := signer.IsImageSigned(tc.imageRef)
		require.Equal(t, tc.isSigned, res, fmt.Sprintf("Checking %s for signature", tc.imageRef))
		if tc.shouldErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestImagesSigned(t *testing.T) {
	signer := sign.New(sign.Default())
	const repo = "k8s.gcr.io/security-profiles-operator/security-profiles-operator"
	for _, tc := range []struct {
		refs      map[string]bool
		shouldErr bool
	}{
		{ // signed single image
			map[string]bool{"ghcr.io/sigstore/cosign/cosign:f436d7637caaa9073522ae65a8416e38cd69c4f2": true},
			false,
		},
		{ // nonexistent
			map[string]bool{"kornotios/supermegafakeimage": false},
			true,
		},
		{ // one valid and one nonexistent
			map[string]bool{
				"ghcr.io/sigstore/cosign/cosign:f436d7637caaa9073522ae65a8416e38cd69c4f2": true,
				"kornotios/supermegafakeimage":                                            false,
			},
			true,
		},
		{ // list of valid images
			map[string]bool{
				repo + ":v0.2.0": false,
				repo + ":v0.3.0": false,
				repo + ":v0.4.0": false,
				repo + ":v0.4.2": false,
				repo + ":v0.4.3": true,
				repo + ":v0.5.0": true,
				repo + "@sha256:4e61cb64ab34d1b80ebdb900c636a2aff60d85c9a48b0f1d34202d9388856bd7": true,
				repo + "@sha256:9da6d7f148b19154fd6df4cc052e6cd52787962369f34c7b0411f77b843f3d4c": true,
			},
			false,
		},
	} {
		refs := []string{}
		for ref := range tc.refs {
			refs = append(refs, ref)
		}

		res, err := signer.ImagesSigned(context.Background(), refs...)
		if tc.shouldErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)

			for ref, expected := range tc.refs {
				signed, ok := res.Load(ref)
				require.True(t, ok)
				require.Equal(t, expected, signed)
			}
		}
	}
}
