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
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
)

// Package contains information about an OBS Package.
type Package struct {
	XMLName     xml.Name `json:"package"               xml:"package"`
	Name        string   `json:"name"                  xml:"name,attr"`
	Project     string   `json:"project"               xml:"project,attr"`
	Title       string   `json:"title,omitempty"       xml:"title,omitempty"`
	Description string   `json:"description,omitempty" xml:"description,omitempty"`
	Devel       *Devel   `json:"devel,omitempty"       xml:"devel,omitempty"`
}

// Devel represents the development information.
type Devel struct {
	Project string `json:"project" xml:"project,attr"`
	Package string `json:"package" xml:"package,attr"`
}

// CreateUpdatePackage creates a new OBS package or updates an existing OBS package of a project.
func (o *OBS) CreateUpdatePackage(ctx context.Context, projectName string, pkg *Package) error {
	xmlData, err := xml.MarshalIndent(pkg, "", " ")
	if err != nil {
		return fmt.Errorf("creating obs package: marshalling package meta: %w", err)
	}

	urlPath, err := url.JoinPath(o.options.APIURL, "source", projectName, pkg.Name, "_meta")
	if err != nil {
		return fmt.Errorf("creating obs package: joining url: %w", err)
	}

	resp, err := o.client.InvokeOBSEndpoint(ctx, o.options.Username, o.options.Password, http.MethodPut, urlPath, bytes.NewBuffer(xmlData))
	if err != nil {
		return fmt.Errorf("creating obs package: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var status Status
		if err := xml.NewDecoder(resp.Body).Decode(&status); err != nil {
			return &APIError{
				HTTPStatusCode: resp.StatusCode,
				OBSStatusCode:  "",
				Message:        fmt.Sprintf("creating obs package: decoding error response: %v", err),
			}
		}

		return &APIError{
			HTTPStatusCode: resp.StatusCode,
			OBSStatusCode:  status.Code,
			Message:        status.Summary,
		}
	}

	return nil
}

// GetPackageMetaFile returns package's meta for a given OBS project.
func (o *OBS) GetPackageMetaFile(ctx context.Context, projectName, packageName string) (*Package, error) {
	urlPath, err := url.JoinPath(o.options.APIURL, "source", projectName, packageName, "_meta")
	if err != nil {
		return nil, fmt.Errorf("getting obs package: joining url: %w", err)
	}

	resp, err := o.client.InvokeOBSEndpoint(ctx, o.options.Username, o.options.Password, http.MethodGet, urlPath, nil)
	if err != nil {
		return nil, fmt.Errorf("getting obs package: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var status Status
		if err := xml.NewDecoder(resp.Body).Decode(&status); err != nil {
			return nil, &APIError{
				HTTPStatusCode: resp.StatusCode,
				OBSStatusCode:  "",
				Message:        fmt.Sprintf("getting obs package: decoding error response: %v", err),
			}
		}

		return nil, &APIError{
			HTTPStatusCode: resp.StatusCode,
			OBSStatusCode:  status.Code,
			Message:        status.Summary,
		}
	}

	pkg := &Package{}
	if err = xml.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return nil, fmt.Errorf("getting obs package: decoding response: %v", err)
	}

	return pkg, nil
}

// DeletePackage deletes an existing OBS package.
func (o *OBS) DeletePackage(ctx context.Context, projectName, packageName string) error {
	urlPath, err := url.JoinPath(o.options.APIURL, "source", projectName, packageName)
	if err != nil {
		return fmt.Errorf("deleting obs package: joining url: %w", err)
	}

	resp, err := o.client.InvokeOBSEndpoint(ctx, o.options.Username, o.options.Password, http.MethodDelete, urlPath, nil)
	if err != nil {
		return fmt.Errorf("deleting obs package: invoking obs endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var status Status
		if err := xml.NewDecoder(resp.Body).Decode(&status); err != nil {
			return &APIError{
				HTTPStatusCode: resp.StatusCode,
				OBSStatusCode:  "",
				Message:        fmt.Sprintf("deleting obs package: decoding error response %v", err),
			}
		}

		return &APIError{
			HTTPStatusCode: resp.StatusCode,
			OBSStatusCode:  status.Code,
			Message:        status.Summary,
		}
	}

	return nil
}
