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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateProjectName(t *testing.T) {
	for _, name := range []string{
		"isv",
		"isv:kubernetes",
		"isv:kubernetes:core:stable",
		"home:xmudrii",
		"openSUSE.org",
		"a-b+c_d",
		"0abc",
		strings.Repeat("a", maxNameLength),
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, validateProjectName(name))
		})
	}

	for _, name := range []string{
		"",
		"0",
		":leading",
		".leading",
		"_leading",
		"trailing:",
		"isv::kubernetes",
		"isv:.kubernetes",
		"isv:_kubernetes",
		"isv kubernetes",
		"isv/kubernetes",
		`isv:kubernetes')]|//*[`,
		strings.Repeat("a", maxNameLength+1),
	} {
		t.Run("invalid "+name, func(t *testing.T) {
			require.Error(t, validateProjectName(name))
		})
	}
}

func TestValidatePackageName(t *testing.T) {
	for _, name := range []string{
		"kubelet",
		"_product",
		"_pattern",
		"_project",
		"_patchinfo",
		"_product:kubernetes",
		"_patchinfo:kubernetes",
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, validatePackageName(name))
		})
	}

	for _, name := range []string{
		"",
		"0",
		"../other",
		"_unknown",
		"_product:",
		"_patchinfo:",
	} {
		t.Run("invalid "+name, func(t *testing.T) {
			require.Error(t, validatePackageName(name))
		})
	}
}
