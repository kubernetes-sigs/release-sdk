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
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/release-sdk/sign"
)

type cleanupFn func() error

func generateCosignKeyPair(t *testing.T, getPassFunc cosign.PassFunc) (string, cleanupFn) {
	tempDir, err := os.MkdirTemp("", "k8s-cosign-keys-")
	require.Nil(t, err)

	keys, err := cosign.GenerateKeyPair(getPassFunc)
	require.Nil(t, err)
	require.NotNil(t, keys)

	keyPath := filepath.Join(tempDir, "cosign.key")
	err = os.WriteFile(keyPath, keys.PrivateBytes, 0o600)
	require.Nil(t, err)

	err = os.WriteFile(filepath.Join(tempDir, "cosign.pub"), keys.PublicBytes, 0o644)
	require.Nil(t, err)

	return keyPath, func() error {
		return os.RemoveAll(tempDir)
	}
}

func TestSuccessSignImage(t *testing.T) {
	imageName := fmt.Sprintf("localhost:5000/honk:%d", time.Now().Unix())
	reg := runDockerRegistryWithDummyImage(t, imageName)
	defer deleteRegistryContainer(t)

	getPass := func(confirm bool) ([]byte, error) {
		return []byte("key-pass"), nil
	}

	// TODO(xmudrii): This can be removed once cosign 1.5.2 or newer is available
	keyPath, cleanup := generateCosignKeyPair(t, getPass)
	defer func() {
		require.Nil(t, cleanup())
	}()

	opts := sign.Default()
	opts.KeyPath = keyPath
	opts.PassFunc = getPass

	signer := sign.New(opts)

	signedObject, err := signer.SignImage(reg.ImageName)
	require.Nil(t, err)
	require.NotNil(t, signedObject)

	verifiedObject, err := signer.Verify(reg.ImageName)
	require.Nil(t, err)
	require.NotNil(t, verifiedObject)
}
