/*
Copyright 2026 The Kubernetes Authors.

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

package obs

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readFixture returns the contents of a testdata file. The fixtures are
// verbatim responses of the reference OBS instance.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)

	return data
}

func TestProjectUnmarshalUmbrella(t *testing.T) {
	project := &Project{}
	require.NoError(t, xml.Unmarshal(readFixture(t, "project_umbrella.xml"), project))

	assert.Equal(t, "isv:kubernetes", project.Name)
	assert.Equal(t, "Kubernetes", project.Title)
	assert.Equal(t, "https://kubernetes.io", project.URL)
	assert.Empty(t, project.Kind)
	assert.Empty(t, project.Repositories)

	// The fixture lists every bugowner before every maintainer, which is why
	// callers must compare people order-insensitively.
	assert.Len(t, project.Persons, 16)
	assert.Equal(t, Person{UserID: "cpanato", Role: RoleBugOwner}, project.Persons[0])
	assert.Equal(t, Person{UserID: "xmudrii", Role: RoleMaintainer}, project.Persons[15])

	// All four flags are disabled without any scoping.
	unscopedDisable := Flag{{Action: FlagActionDisable}}
	assert.Equal(t, unscopedDisable, project.Build)
	assert.Equal(t, unscopedDisable, project.Publish)
	assert.Equal(t, unscopedDisable, project.DebugInfo)
	assert.Equal(t, unscopedDisable, project.UseForBuild)
	assert.Nil(t, project.BinaryDownload)
}

func TestProjectUnmarshalRelease(t *testing.T) {
	project := &Project{}
	require.NoError(t, xml.Unmarshal(readFixture(t, "project_release.xml"), project))

	assert.Equal(t, "isv:kubernetes:core:stable:v1.34", project.Name)
	assert.Equal(t, ProjectKindMaintenanceRelease, project.Kind)
	assert.Equal(t, Flag{{Action: FlagActionDisable}}, project.Build)
	require.Len(t, project.Repositories, 2)

	rpm := project.Repositories[0]
	assert.Equal(t, testRPMRepository, rpm.Name)
	assert.Empty(t, rpm.ReleaseTargets)
	assert.Equal(t, []RepositoryPath{{Project: "SUSE:SLE-15-SP5:GA", Repository: "standard"}}, rpm.Paths)
	assert.Equal(t, []string{testArchitectureX8664, "aarch64", "ppc64le", testArchitectureS390X}, rpm.Architectures)

	// The deb repository of this project lists the architectures in a different
	// order than the rpm one, which the client must preserve verbatim.
	assert.Equal(
		t,
		[]string{testArchitectureX8664, "aarch64", testArchitectureS390X, "ppc64le"},
		project.Repositories[1].Architectures,
	)
}

func TestProjectUnmarshalBuilder(t *testing.T) {
	project := &Project{}
	require.NoError(t, xml.Unmarshal(readFixture(t, "project_builder.xml"), project))

	assert.Equal(t, testBuilderProjectName, project.Name)
	assert.Empty(t, project.Kind)
	assert.Nil(t, project.Build)
	require.Len(t, project.Repositories, 2)

	deb := project.Repositories[1]
	assert.Equal(t, "deb", deb.Name)
	assert.Equal(t, []ReleaseTarget{{
		Project:    "isv:kubernetes:core:stable:v1.34",
		Repository: "deb",
		Trigger:    ReleaseTriggerManual,
	}}, deb.ReleaseTargets)
	assert.Equal(t, []RepositoryPath{
		{Project: "Ubuntu:20.04", Repository: "universe"},
		{Project: "Ubuntu:debbuild", Repository: "Ubuntu_20.04"},
	}, deb.Paths)
}

// TestProjectRoundTrip ensures that decoding and re-encoding a live meta
// document does not lose or reorder anything the type models.
func TestProjectRoundTrip(t *testing.T) {
	for _, fixture := range []string{"project_umbrella.xml", "project_release.xml", "project_builder.xml"} {
		t.Run(fixture, func(t *testing.T) {
			original := &Project{}
			require.NoError(t, xml.Unmarshal(readFixture(t, fixture), original))

			encoded, err := xml.Marshal(original)
			require.NoError(t, err)

			decoded := &Project{}
			require.NoError(t, xml.Unmarshal(encoded, decoded))

			assert.Equal(t, original, decoded)
		})
	}
}

// TestProjectMinimalMeta pins the minimal project meta, which is what is sent
// to create a project before its full meta is applied.
func TestProjectMinimalMeta(t *testing.T) {
	encoded, err := xml.Marshal(&Project{Name: testCoreProjectName})
	require.NoError(t, err)

	assert.Equal(
		t,
		`<project name="isv:kubernetes:core"><title></title><description></description></project>`,
		string(encoded),
	)
}

func TestPackageUnmarshalMinimal(t *testing.T) {
	pkg := &Package{}
	require.NoError(t, xml.Unmarshal(readFixture(t, "package_minimal.xml"), pkg))

	assert.Equal(t, testPackageName, pkg.Name)
	assert.Equal(t, testBuilderProjectName, pkg.Project)
	assert.Empty(t, pkg.Title)
	assert.Empty(t, pkg.Description)
	assert.Nil(t, pkg.Devel)
}

// TestPackageMinimalMeta pins the minimal package meta, which is the desired
// state of a package declared by name only.
func TestPackageMinimalMeta(t *testing.T) {
	encoded, err := xml.Marshal(&Package{Name: testPackageName})
	require.NoError(t, err)

	assert.Equal(
		t,
		`<package name="kubelet"><title></title><description></description></package>`,
		string(encoded),
	)
}

func TestDirectoryUnmarshal(t *testing.T) {
	directory := &Directory{}
	require.NoError(t, xml.Unmarshal(readFixture(t, "directory_packages.xml"), directory))

	names := make([]string, 0, len(directory.Entries))
	for _, entry := range directory.Entries {
		names = append(names, entry.Name)
	}

	// The builder project contains regular packages next to release copies.
	assert.Contains(t, names, testPackageName)
	assert.Contains(t, names, "kubernetes-cni.20250828170903")
	assert.Equal(
		t,
		[]string{testCRItoolsPackage, testKubeadmPackage, testKubectlPackage, testPackageName},
		FilterReleaseCopies(names),
	)
}

func TestProjectCollectionUnmarshal(t *testing.T) {
	collection := &ProjectCollection{}
	require.NoError(t, xml.Unmarshal([]byte(
		`<collection matches="2"><project name="isv:kubernetes"/><project name="isv:kubernetes:core"/></collection>`,
	), collection))

	assert.Equal(t, 2, collection.Matches)
	assert.Equal(t, []ProjectID{{Name: "isv:kubernetes"}, {Name: "isv:kubernetes:core"}}, collection.Projects)
}
