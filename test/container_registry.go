package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/command"
)

const (
	testDockerfile = `FROM scratch
CMD [""]
`
	testDockerfileName    = "Dockerfile"
	registryImage         = "registry:2"
	registryContainerName = "k8s-registry"
)

type dockerRegistry struct {
	ImageName      string
	DockerfilePath string
}

func RunDockerRegistryWithDummyImage(t *testing.T, imageName string) *dockerRegistry {
	// Setup the Docker Registry
	cmd := command.New("docker", "run", "--detach", "--network", "host",
		"--name", registryContainerName, registryImage)
	err := cmd.RunSuccess()
	require.Nil(t, err)

	// Setup the temp dir
	tempDir, err := os.MkdirTemp("", "k8s-test-img-")
	require.Nil(t, err)

	// Add the image
	require.Nil(t, os.WriteFile(
		filepath.Join(tempDir, testDockerfileName),
		[]byte(testDockerfile),
		os.FileMode(0o644),
	))

	// Build the image
	cmd = command.New("docker", "build", "--tag", imageName, tempDir)
	err = cmd.RunSuccess()
	require.Nil(t, err)

	// Push the image
	cmd = command.New("docker", "push", imageName)
	err = cmd.RunSuccess()
	require.Nil(t, err)

	return &dockerRegistry{
		ImageName:      imageName,
		DockerfilePath: tempDir,
	}
}

func DeleteRegistryContainer(t *testing.T) {
	cmd := command.New("docker", "rm", "-f", registryContainerName)
	err := cmd.RunSuccess()
	require.Nil(t, err)
}
