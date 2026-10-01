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
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testCRItoolsPackage      = "cri-tools"
	testKubeadmPackage       = "kubeadm"
	testKubectlPackage       = "kubectl"
	testKubernetesCNIPackage = "kubernetes-cni"
	testPythonPackage        = "python3.13"
)

func TestIsReleaseCopy(t *testing.T) {
	testcases := []struct {
		name         string
		packageName  string
		isCopy       bool
		expectedBase string
	}{
		{
			name:         "regular package",
			packageName:  testKubeadmPackage,
			isCopy:       false,
			expectedBase: testKubeadmPackage,
		},
		{
			name:         "regular package with a dash",
			packageName:  testKubernetesCNIPackage,
			isCopy:       false,
			expectedBase: testKubernetesCNIPackage,
		},
		{
			name:         "single timestamp suffix",
			packageName:  "kubeadm.20260923195931",
			isCopy:       true,
			expectedBase: testKubeadmPackage,
		},
		{
			name:         "several timestamp suffixes",
			packageName:  "kubernetes-cni.20260424110236.20260424140455",
			isCopy:       true,
			expectedBase: testKubernetesCNIPackage,
		},
		{
			name:         "dotted package name without a timestamp",
			packageName:  testPythonPackage,
			isCopy:       false,
			expectedBase: testPythonPackage,
		},
		{
			name:         "suffix that is too short",
			packageName:  "kubeadm.2026092319593",
			isCopy:       false,
			expectedBase: "kubeadm.2026092319593",
		},
		{
			name:         "suffix that is too long",
			packageName:  "kubeadm.202609231959311",
			isCopy:       false,
			expectedBase: "kubeadm.202609231959311",
		},
		{
			name:         "non numeric suffix",
			packageName:  "kubeadm.2026092319593x",
			isCopy:       false,
			expectedBase: "kubeadm.2026092319593x",
		},
		{
			name:         "dotted package name with a timestamp",
			packageName:  "python3.13.20260923195931",
			isCopy:       true,
			expectedBase: testPythonPackage,
		},
		{
			name:         "timestamp without a base name",
			packageName:  "20260923195931",
			isCopy:       false,
			expectedBase: "20260923195931",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.isCopy, IsReleaseCopy(tc.packageName))

			base, isCopy := ReleaseCopyBase(tc.packageName)
			assert.Equal(t, tc.isCopy, isCopy)
			assert.Equal(t, tc.expectedBase, base)
		})
	}
}

func TestFilterReleaseCopies(t *testing.T) {
	// The package list of a live builder project, which contains release copies
	// next to the regular packages it builds.
	packages := []string{
		testCRItoolsPackage,
		testKubeadmPackage,
		testKubectlPackage,
		testPackageName,
		"kubernetes-cni.20241211190905",
		"kubernetes-cni.20250828170903",
		"kubernetes-cni.20250828170904",
	}

	assert.Equal(
		t,
		[]string{testCRItoolsPackage, testKubeadmPackage, testKubectlPackage, testPackageName},
		FilterReleaseCopies(packages),
	)
}

func TestFilterReleaseCopiesEmpty(t *testing.T) {
	assert.Empty(t, FilterReleaseCopies(nil))
	assert.Empty(t, FilterReleaseCopies([]string{"kubeadm.20260923195931"}))
}
