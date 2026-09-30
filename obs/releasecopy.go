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

import "regexp"

// releaseCopyRegex matches a package name produced by the OBS release
// mechanism: a package name followed by one or more timestamp suffixes, such
// as kubeadm.20260923195931 or
// kubernetes-cni.20260424110236.20260424140455.
//
// The base name is non-greedy, so the first submatch is the original name even
// when several suffixes are present.
var releaseCopyRegex = regexp.MustCompile(`^(.+?)(?:\.\d{14})+$`)

// IsReleaseCopy reports whether the package name is a copy created by the OBS
// release mechanism.
//
// Release copies are managed entirely by OBS, so a tool reconciling package
// lists must never create, compare or delete them. Builder projects can
// contain them alongside regular packages.
func IsReleaseCopy(packageName string) bool {
	return releaseCopyRegex.MatchString(packageName)
}

// ReleaseCopyBase returns the name of the package a release copy was made
// from, and whether the name was a release copy at all. A name that is not one
// is returned unchanged.
//
// OBS builds the copy from releasename || name, so for a package carrying a
// releasename this returns that, not the package name.
func ReleaseCopyBase(packageName string) (string, bool) {
	match := releaseCopyRegex.FindStringSubmatch(packageName)
	if match == nil {
		return packageName, false
	}

	return match[1], true
}

// FilterReleaseCopies returns the given package names without release copies,
// preserving order.
func FilterReleaseCopies(packageNames []string) []string {
	filtered := make([]string, 0, len(packageNames))

	for _, name := range packageNames {
		if !IsReleaseCopy(name) {
			filtered = append(filtered, name)
		}
	}

	return filtered
}
