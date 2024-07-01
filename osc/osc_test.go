/*
Copyright 2024 The Kubernetes Authors.

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

package osc_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-sdk/osc"
)

const (
	pathKey     = "PATH"
	testProject = "project"
	testPackage = "package"
)

func TestWaitResults(t *testing.T) {
	for _, version := range []string{"1.6.2", "1.8.0"} {
		// Setup a custom OSC executable
		tempDir, err := os.MkdirTemp("", "osc-version-test-")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(
			filepath.Join(tempDir, osc.OSCExecutable),
			[]byte(`#!/usr/bin/env sh

if [ "$1" = version ]; then
    echo -n `+version+`
else
    echo -n "$@" > $(dirname "$(realpath $0)")/res
fi
	`),
			0o755))

		// Change $PATH
		pathEnv := os.Getenv(pathKey)
		t.Setenv(pathKey, tempDir+":"+pathEnv)

		// Run the version test
		ver, err := osc.Version()
		assert.NoError(t, err)
		assert.True(t, ver.EQ(semver.MustParse(version)))

		// Run the wait results test
		err = osc.WaitResults(testProject, testPackage)
		assert.NoError(t, err)
		res, err := os.ReadFile(filepath.Join(tempDir, "res"))
		assert.NoError(t, err)
		testString := "results -w project/package"
		if version == "1.8.0" {
			testString += " -F"
		}
		assert.Equal(t, testString, string(res))

		// Cleanup
		require.Nil(t, os.RemoveAll(tempDir))
	}
}
