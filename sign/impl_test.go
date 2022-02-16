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

package sign

import (
	"fmt"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestIsImageSigned(t *testing.T) {
	signer := New(Default())
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

func TestFileExists(t *testing.T) {
	f, err := os.CreateTemp("", "test-")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	require.NoError(t, os.WriteFile(f.Name(), []byte("hey"), os.FileMode(0o644)))
	sut := &defaultImpl{log: logrus.New()}
	require.True(t, sut.FileExists(f.Name()))
	require.False(t, sut.FileExists(f.Name()+"a"))
}
