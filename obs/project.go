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
	"io"
	"net/http"
	"net/url"
)

type Project struct {
	XMLName      xml.Name     `json:"project" xml:"project"`
	Name         string       `json:"name" xml:"name,attr"`
	Kind         string       `json:"kind,omitempty" xml:"kind,attr,omitempty"`
	Title        string       `json:"title,omitempty" xml:"title,omitempty"`
	Description  string       `json:"description,omitempty" xml:"description,omitempty"`
	URL          string       `json:"url,omitempty" xml:"url,omitempty"`
	Persons      []Person     `json:"persons,omitempty" xml:"person,omitempty"`
	Repositories []Repository `json:"repositories,omitempty" xml:"repository,omitempty"`
	Build        *Build       `json:"build,omitempty" xml:"build,omitempty"`
	Publish      *Publish     `json:"publish,omitempty" xml:"publish,omitempty"`
	DebugInfo    *DebugInfo   `json:"debugInfo,omitempty" xml:"debuginfo,omitempty"`
	UseForBuild  *UseForBuild `json:"useForBuild,omitempty" xml:"useforbuild,omitempty"`
}

type Client struct {
	Client   http.Client
	Username string
	Password string
	APIURL   string
}

type Disabled struct{}

type Build struct {
	Disable *Disabled `json:"disable,omitempty" xml:"disable,omitempty"`
}

type Publish struct {
	Disable *Disabled `json:"disable,omitempty" xml:"disable,omitempty"`
}

type DebugInfo struct {
	Disable *Disabled `json:"disable,omitempty" xml:"disable,omitempty"`
}

type UseForBuild struct {
	Disable *Disabled `json:"disable,omitempty" xml:"disable,omitempty"`
}

type Person struct {
	UserID string     `json:"userid" xml:"userid,attr"`
	Role   PersonRole `json:"role" xml:"role,attr"`
}

type PersonRole string

const (
	PersonRoleBugOwner   PersonRole = "bugowner"
	PersonRoleMaintainer PersonRole = "maintainer"
	PersonRoleReviewer   PersonRole = "reviewer"
	PersonRoleDownloader PersonRole = "downloader"
	PersonRoleReader     PersonRole = "reader"
)

type Repository struct {
	Repository     string           `json:"name" xml:"name,attr"`
	Architectures  []string         `json:"architectures" xml:"arch"`
	ReleaseTargets []ReleaseTarget  `json:"releaseTargets,omitempty" xml:"releasetarget,omitempty"`
	Paths          []RepositoryPath `json:"path,omitempty" xml:"path,omitempty"`
}

type ReleaseTarget struct {
	ProjectName string `json:"project" xml:"project,attr"`
	Repository  string `json:"repository" xml:"repository,attr"`
	Trigger     string `json:"trigger" xml:"trigger,attr"`
}

type RepositoryPath struct {
	Project    string `json:"project" xml:"project,attr"`
	Repository string `json:"repository" xml:"repository,attr"`
}

// CreateUpdateProject is used to create the project and update the existing obs project
func (c *Client) CreateUpdateProject(ctx context.Context, project *Project) error {
	xmlData, err := xml.MarshalIndent(project, "", " ")
	if err != nil {
		return fmt.Errorf("creating obs project: marshalling project meta: %w", err)
	}

	urlPath, err := url.JoinPath(c.APIURL, "source", project.Name, "_meta")
	if err != nil {
		return fmt.Errorf("creating obs project: joining url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, urlPath, bytes.NewBuffer(xmlData))
	if err != nil {
		return &APIError{
			HTTPStatusCode: 0,
			OBSStatusCode:  "",
			Message:        fmt.Sprintf("creating obs project: creating request: %v", err),
		}
	}

	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Accept", "application/xml; charset=utf-8")

	resp, err := c.Client.Do(req)
	if err != nil {
		return &APIError{
			HTTPStatusCode: 0,
			OBSStatusCode:  "",
			Message:        fmt.Sprintf("creating obs project: sending request: %v", err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var status Status
		if err := xml.NewDecoder(resp.Body).Decode(&status); err != nil {
			return &APIError{
				HTTPStatusCode: resp.StatusCode,
				OBSStatusCode:  "",
				Message:        fmt.Sprintf("creating obs project: decoding error response: %v", err),
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

// GetProjectMetaFile is used to get the contents of the obs project meta file
func (c *Client) GetProjectMetaFile(ctx context.Context, project *Project) ([]byte, error) {
	urlPath, err := url.JoinPath(c.APIURL, "source", project.Name, "_meta")
	if err != nil {
		return nil, fmt.Errorf("getting obs project: joining url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlPath, http.NoBody)
	if err != nil {
		return nil, &APIError{
			HTTPStatusCode: 0,
			OBSStatusCode:  "",
			Message:        fmt.Sprintf("getting obs project: creating request: %v", err),
		}
	}

	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Accept", "application/xml; charset=utf-8")

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, &APIError{
			HTTPStatusCode: 0,
			OBSStatusCode:  "",
			Message:        fmt.Sprintf("getting obs project: sending request: %v", err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var status Status
		if err := xml.NewDecoder(resp.Body).Decode(&status); err != nil {
			return nil, &APIError{
				HTTPStatusCode: resp.StatusCode,
				OBSStatusCode:  "",
				Message:        fmt.Sprintf("getting obs project: decoding error response: %v", err),
			}
		}

		return nil, &APIError{
			HTTPStatusCode: resp.StatusCode,
			OBSStatusCode:  status.Code,
			Message:        status.Summary,
		}
	}

	metaFile, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getting obs project meta file: reading response body: %v", err)
	}

	return metaFile, nil
}

// DeleteProject is used to delete the existing obs project
func (c *Client) DeleteProject(ctx context.Context, project *Project) error {
	urlPath, err := url.JoinPath(c.APIURL, "source", project.Name)
	if err != nil {
		return fmt.Errorf("deleting obs project: joining url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlPath, http.NoBody)
	if err != nil {
		return &APIError{
			HTTPStatusCode: 0,
			OBSStatusCode:  "",
			Message:        fmt.Sprintf("deleting obs project: creating request: %v", err),
		}
	}

	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Accept", "application/xml; charset=utf-8")

	resp, err := c.Client.Do(req)
	if err != nil {
		return &APIError{
			HTTPStatusCode: 0,
			OBSStatusCode:  "",
			Message:        fmt.Sprintf("deleting obs project: sending request: %v", err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var status Status
		if err := xml.NewDecoder(resp.Body).Decode(&status); err != nil {
			return &APIError{
				HTTPStatusCode: resp.StatusCode,
				OBSStatusCode:  "",
				Message:        fmt.Sprintf("deleting obs project: decoding error response %v", err),
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
