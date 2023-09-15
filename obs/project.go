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
	"encoding/xml"
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
	Architectures  []string         `json:"arch" xml:"arch"`
	ReleaseTargets []ReleaseTarget  `json:"releasetarget,omitempty" xml:"releasetarget,omitempty"`
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
