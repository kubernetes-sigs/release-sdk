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
	"sigs.k8s.io/release-sdk/test"
)

func generateCosignKey(t *testing.T, getPassFunc cosign.PassFunc) string {
	tempDir, err := os.MkdirTemp("", "k8s-cosign-keys-")
	require.Nil(t, err)

	keys, err := cosign.GenerateKeyPair(getPassFunc)
	require.Nil(t, err)
	require.NotNil(t, keys)

	err = os.WriteFile(filepath.Join(tempDir, "cosign.key"), keys.PrivateBytes, 0600)
	require.Nil(t, err)

	err = os.WriteFile(filepath.Join(tempDir, "cosign.pub"), keys.PublicBytes, 0644)
	require.Nil(t, err)

	return tempDir
}

func TestSuccessSignImage(t *testing.T) {
	imageName := fmt.Sprintf("%s:%d", "localhost:5000/honk", time.Now().Unix())
	reg := test.RunDockerRegistryWithDummyImage(t, imageName)
	defer test.DeleteRegistryContainer(t)

	getPass := func(confirm bool) ([]byte, error) {
		return []byte("key-pass"), nil
	}

	keyPath := generateCosignKey(t, getPass)

	opts := sign.Default()
	opts.KeyPath = filepath.Join(keyPath, "cosign.key")
	opts.PassFunc = getPass

	signer := sign.New(opts)

	signedObject, err := signer.SignImage(reg.ImageName)
	require.Nil(t, err)
	require.NotNil(t, signedObject)
}
