//go:build e2e
// +build e2e

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

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/release-sdk/sign"
)

const (
	ociManifestType   = "application/vnd.oci.image.manifest.v1+json"
	registry          = "localhost:5000"
	imageName         = "test"
	registryWithImage = registry + "/" + imageName
	imageRef          = registryWithImage + ":latest"
)

func TestSignImageSuccess(t *testing.T) {
	// Test the prerequisites
	opts := sign.Default()
	opts.IgnoreTlog = true
	opts.CertIdentityRegexp = "https://github.com/kubernetes-sigs/release-sdk/.github/workflows/e2e.yml@.*"
	opts.CertOidcIssuer = "https://token.actions.githubusercontent.com"

	signer := sign.New(opts)
	signed, err := signer.IsImageSigned(imageRef)
	require.Nil(t, err)
	require.False(t, signed)

	// Sign the image
	res, err := signer.SignImage(imageRef)

	// Verify the results
	assert.Nil(t, err)
	assert.Nil(t, res.File())
	image := res.Image()
	assert.NotNil(t, image)
	assert.Equal(t, imageRef, image.Reference())
	assert.Regexp(t, `sha256:[[:xdigit:]]{64}`, image.Digest())
	assert.Regexp(t, registryWithImage+`:sha256-[[:xdigit:]]{64}\.sig`, image.Signature())

	url := fmt.Sprintf(
		"http://%s/v2/%s/manifests/%s",
		registry,
		imageName,
		strings.Replace(image.Signature(), registryWithImage+":", "", 1),
	)
	fmt.Printf(": %s\n", url)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	require.Nil(t, err)
	req.Header.Set("Accept", ociManifestType)

	resp, err := client.Do(req)
	require.Nil(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)

	response := string(body)
	assert.Contains(t, response, "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, response, "-----END CERTIFICATE-----")
	assert.Contains(t, response, fmt.Sprintf(`"mediaType":"%s"`, ociManifestType))

	signed, err = signer.IsImageSigned(imageRef)
	require.Nil(t, err)
	assert.True(t, signed)

	obj, err := signer.VerifyImage(imageRef)
	require.Nil(t, err)
	assert.Equal(t, res, obj)
}

func TestSignImageFailureWrongImageRef(t *testing.T) {
	// Test the prerequisites
	signer := sign.New(nil)
	_, err := signer.SignImage(registry + "/not-existing:latest")
	assert.ErrorContains(t, err, "entity not found in registry")
}
