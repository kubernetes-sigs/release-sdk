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

type Project struct {
	XMLName      xml.Name     `json:"project"                xml:"project"`
	Name         string       `json:"name"                   xml:"name,attr"`
	Kind         string       `json:"kind,omitempty"         xml:"kind,attr,omitempty"`
	Title        string       `json:"title,omitempty"        xml:"title,omitempty"`
	Description  string       `json:"description,omitempty"  xml:"description,omitempty"`
	URL          string       `json:"url,omitempty"          xml:"url,omitempty"`
	Persons      []Person     `json:"persons,omitempty"      xml:"person,omitempty"`
	Repositories []Repository `json:"repositories,omitempty" xml:"repository,omitempty"`
	Build        *Build       `json:"build,omitempty"        xml:"build,omitempty"`
	Publish      *Publish     `json:"publish,omitempty"      xml:"publish,omitempty"`
	DebugInfo    *DebugInfo   `json:"debugInfo,omitempty"    xml:"debuginfo,omitempty"`
	UseForBuild  *UseForBuild `json:"useForBuild,omitempty"  xml:"useforbuild,omitempty"`
}

// OBS is a wrapper around OBS related functionality.
type OBS struct {
	client  Client
	options *Options
}

type obsClient struct {
	*http.Client
}

// Client is an interface modeling supported OBS operations.
type Client interface {
	InvokeOBSEndpoint(ctx context.Context, username, password, method, apiURL string, xml *bytes.Buffer) (*http.Response, error)
}

// InvokeOBSEndpoint invokes an OBS endpoint by making a HTTP request.
func (o *obsClient) InvokeOBSEndpoint(ctx context.Context, username, password, method, apiURL string, xmlData *bytes.Buffer) (*http.Response, error) {
	if xmlData == nil {
		xmlData = &bytes.Buffer{}
	}

	req, err := http.NewRequestWithContext(ctx, method, apiURL, xmlData)
	if err != nil {
		return nil, &APIError{
			HTTPStatusCode: 0,
			OBSStatusCode:  "",
			Message:        fmt.Sprintf("creating request: %v", err),
		}
	}

	req.SetBasicAuth(username, password)
	req.Header.Set("Accept", "application/xml; charset=utf-8")

	resp, err := o.Client.Do(req)
	if err != nil {
		return nil, &APIError{
			HTTPStatusCode: 0,
			OBSStatusCode:  "",
			Message:        fmt.Sprintf("sending request: %v", err),
		}
	}

	return resp, nil
}

// Options is a set of options to configure the behavior of the OBS package.
type Options struct {
	Username string
	Password string
	APIURL   string
}

// DefaultOptions return an options struct with commonly used settings.
func DefaultOptions() *Options {
	return &Options{
		APIURL: "https://api.opensuse.org/",
	}
}

// New creates a new default OBS client.
func New(opts *Options) *OBS {
	return &OBS{
		client:  &obsClient{Client: http.DefaultClient},
		options: opts,
	}
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
	Role   PersonRole `json:"role"   xml:"role,attr"`
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
	Repository     string           `json:"name"                     xml:"name,attr"`
	Architectures  []string         `json:"architectures"            xml:"arch"`
	ReleaseTargets []ReleaseTarget  `json:"releaseTargets,omitempty" xml:"releasetarget,omitempty"`
	Paths          []RepositoryPath `json:"path,omitempty"           xml:"path,omitempty"`
}

type ReleaseTarget struct {
	ProjectName string `json:"project"    xml:"project,attr"`
	Repository  string `json:"repository" xml:"repository,attr"`
	Trigger     string `json:"trigger"    xml:"trigger,attr"`
}

type RepositoryPath struct {
	Project    string `json:"project"    xml:"project,attr"`
	Repository string `json:"repository" xml:"repository,attr"`
}

// CreateUpdateProject creates a new OBS project or updates an existing OBS project.
func (o *OBS) CreateUpdateProject(ctx context.Context, project *Project) error {
	xmlData, err := xml.MarshalIndent(project, "", " ")
	if err != nil {
		return fmt.Errorf("creating obs project: marshalling project meta: %w", err)
	}

	urlPath, err := url.JoinPath(o.options.APIURL, "source", project.Name, "_meta")
	if err != nil {
		return fmt.Errorf("creating obs project: joining url: %w", err)
	}

	resp, err := o.client.InvokeOBSEndpoint(ctx, o.options.Username, o.options.Password, http.MethodPut, urlPath, bytes.NewBuffer(xmlData))
	if err != nil {
		return fmt.Errorf("creating obs project: %w", err)
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

// GetProjectMetaFile returns project's meta for a given OBS project.
func (o *OBS) GetProjectMetaFile(ctx context.Context, projectName string) (*Project, error) {
	urlPath, err := url.JoinPath(o.options.APIURL, "source", projectName, "_meta")
	if err != nil {
		return nil, fmt.Errorf("getting obs project: joining url: %w", err)
	}

	resp, err := o.client.InvokeOBSEndpoint(ctx, o.options.Username, o.options.Password, http.MethodGet, urlPath, nil)
	if err != nil {
		return nil, fmt.Errorf("getting obs project: %w", err)
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

	var project Project
	if err = xml.NewDecoder(resp.Body).Decode(&project); err != nil {
		return nil, fmt.Errorf("getting obs project: decoding response: %w", err)
	}

	return &project, nil
}

// DeleteProject deletes an existing OBS project.
func (o *OBS) DeleteProject(ctx context.Context, project *Project) error {
	urlPath, err := url.JoinPath(o.options.APIURL, "source", project.Name)
	if err != nil {
		return fmt.Errorf("deleting obs project: joining url: %w", err)
	}

	resp, err := o.client.InvokeOBSEndpoint(ctx, o.options.Username, o.options.Password, http.MethodDelete, urlPath, nil)
	if err != nil {
		return fmt.Errorf("deleting obs project: %w", err)
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
