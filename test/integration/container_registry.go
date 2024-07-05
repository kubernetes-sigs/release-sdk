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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/release-utils/command"
)

const (
	dockerfile = `
FROM scratch
CMD [""]
`

	dockerCommand  = "docker"
	dockerfileName = "Dockerfile"

	registryImage         = "registry:2"
	registryContainerName = "k8s-registry"
)

type dockerRegistry struct {
	ImageName      string
	DockerfilePath string
}

func runDockerRegistryWithDummyImage(t *testing.T, imageName string) *dockerRegistry {
	// Setup the Docker Registry
	cmd := command.New(dockerCommand, "run", "--detach", "--network", "host",
		"--name", registryContainerName, registryImage)
	err := cmd.RunSuccess()
	require.NoError(t, err)

	// Setup the temp dir
	tempDir, err := os.MkdirTemp("", "k8s-test-img-")
	require.NoError(t, err)

	// Add the image
	require.NoError(t, os.WriteFile(
		filepath.Join(tempDir, dockerfileName),
		[]byte(dockerfile),
		os.FileMode(0o644),
	))

	// Build the image
	cmd = command.New(dockerCommand, "build", "--tag", imageName, tempDir)
	err = cmd.RunSuccess()
	require.NoError(t, err)

	// Push the image
	cmd = command.New(dockerCommand, "push", imageName)
	err = cmd.RunSuccess()
	require.NoError(t, err)

	// After the image is pushed, we don't need the Dockerfile any longer
	require.NoError(t, os.RemoveAll(tempDir))

	return &dockerRegistry{
		ImageName:      imageName,
		DockerfilePath: tempDir,
	}
}

func deleteRegistryContainer(t *testing.T) {
	cmd := command.New(dockerCommand, "rm", "-f", registryContainerName)
	err := cmd.RunSuccess()
	require.NoError(t, err)
}
