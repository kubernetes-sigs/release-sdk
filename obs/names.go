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
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// maxNameLength is the limit OBS enforces in Project.valid_name? and
// Package.valid_name?, and the width of the name column in its database.
const maxNameLength = 200

var (
	projectNameRegex         = regexp.MustCompile(`^[-+\w.:]+$`)
	packageNameRegex         = regexp.MustCompile(`^(?:[a-zA-Z0-9]|(?:_product:|_patchinfo:)\w)[-+\w.]*$`)
	invalidSegmentStartRegex = regexp.MustCompile(`:[:._]`)
)

// validateProjectName applies the project name rules enforced by OBS.
func validateProjectName(name string) error {
	if name == "" {
		return errors.New("project name must not be empty")
	}

	if name == "0" || len(name) > maxNameLength ||
		strings.HasSuffix(name, ":") ||
		strings.ContainsAny(name[:1], ":._") ||
		invalidSegmentStartRegex.MatchString(name) ||
		!projectNameRegex.MatchString(name) {
		return fmt.Errorf("invalid project name %q", name)
	}

	return nil
}

// validatePackageName applies the package name rules enforced by OBS.
func validatePackageName(name string) error {
	if name == "" {
		return errors.New("package name must not be empty")
	}

	if name == "0" || len(name) > maxNameLength ||
		!isSpecialPackageName(name) && !packageNameRegex.MatchString(name) {
		return fmt.Errorf("invalid package name %q", name)
	}

	return nil
}

// isSpecialPackageName reports whether name is one of the package containers
// OBS treats specially.
func isSpecialPackageName(name string) bool {
	switch name {
	case "_product", "_pattern", "_project", "_patchinfo":
		return true
	default:
		return false
	}
}
