/*
Copyright 2023 The Kubernetes Authors.

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
	"context"
	"encoding/xml"
	"errors"
	"fmt"
)

// Package is the meta document of an OBS package, limited to the elements
// modeled here.
type Package struct {
	XMLName        xml.Name `json:"-"                        xml:"package"`
	Name           string   `json:"name"                     xml:"name,attr"`
	Project        string   `json:"project,omitempty"        xml:"project,attr,omitempty"`
	Title          string   `json:"title"                    xml:"title"`
	Description    string   `json:"description"              xml:"description"`
	URL            string   `json:"url,omitempty"            xml:"url,omitempty"`
	Devel          *Devel   `json:"devel,omitempty"          xml:"devel,omitempty"`
	ReleaseName    string   `json:"releaseName,omitempty"    xml:"releasename,omitempty"`
	Persons        []Person `json:"persons,omitempty"        xml:"person,omitempty"`
	Groups         []Group  `json:"groups,omitempty"         xml:"group,omitempty"`
	Build          Flag     `json:"build,omitempty"          xml:"build,omitempty"`
	Publish        Flag     `json:"publish,omitempty"        xml:"publish,omitempty"`
	UseForBuild    Flag     `json:"useForBuild,omitempty"    xml:"useforbuild,omitempty"`
	DebugInfo      Flag     `json:"debugInfo,omitempty"      xml:"debuginfo,omitempty"`
	BinaryDownload Flag     `json:"binaryDownload,omitempty" xml:"binarydownload,omitempty"`
	BcntSyncTag    string   `json:"bcntSyncTag,omitempty"    xml:"bcntsynctag,omitempty"`
}

// Devel points at the project and package where the package is developed.
type Devel struct {
	Project string `json:"project"           xml:"project,attr"`
	Package string `json:"package,omitempty" xml:"package,attr,omitempty"`
}

// GetPackageMeta returns the meta of the given package. Use IsNotFound on the
// returned error to check whether the package exists.
func (o *OBS) GetPackageMeta(ctx context.Context, projectName, packageName string) (*Package, error) {
	if err := validateProjectName(projectName); err != nil {
		return nil, err
	}

	if err := validatePackageName(packageName); err != nil {
		return nil, err
	}

	pkg := &Package{}
	if err := o.get(ctx, pkg, nil, "source", projectName, packageName, "_meta"); err != nil {
		return nil, fmt.Errorf("getting meta of package %s/%s: %w", projectName, packageName, err)
	}

	return pkg, nil
}

// PutPackageMeta creates the package in its project or updates its meta. OBS
// replaces the whole document, so elements Package does not model are dropped.
func (o *OBS) PutPackageMeta(ctx context.Context, pkg *Package) error {
	if pkg == nil {
		return errors.New("package must not be nil")
	}

	if err := validateProjectName(pkg.Project); err != nil {
		return err
	}

	if err := validatePackageName(pkg.Name); err != nil {
		return err
	}

	if err := o.put(ctx, pkg, "source", pkg.Project, pkg.Name, "_meta"); err != nil {
		return fmt.Errorf("putting meta of package %s/%s: %w", pkg.Project, pkg.Name, err)
	}

	return nil
}

// DeletePackage deletes the given package from the given project.
func (o *OBS) DeletePackage(ctx context.Context, projectName, packageName string) error {
	if err := validateProjectName(projectName); err != nil {
		return err
	}

	if err := validatePackageName(packageName); err != nil {
		return err
	}

	if err := o.delete(ctx, "source", projectName, packageName); err != nil {
		return fmt.Errorf("deleting package %s/%s: %w", projectName, packageName, err)
	}

	return nil
}
