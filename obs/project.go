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
	"net/url"
)

// ProjectKind is the kind attribute of a project.
type ProjectKind string

const (
	// ProjectKindStandard is a regular project. It is the OBS default and is
	// represented by an absent kind attribute.
	ProjectKindStandard ProjectKind = "standard"

	// ProjectKindMaintenance is a maintenance project.
	ProjectKindMaintenance ProjectKind = "maintenance"

	// ProjectKindMaintenanceIncident is a maintenance incident project.
	ProjectKindMaintenanceIncident ProjectKind = "maintenance_incident"

	// ProjectKindMaintenanceRelease is a maintenance release project, the target
	// of a release operation.
	ProjectKindMaintenanceRelease ProjectKind = "maintenance_release"
)

// Role is a role that can be assigned to a user or a group on a project or a
// package.
type Role string

const (
	// RoleMaintainer may modify the project or package, including its meta.
	RoleMaintainer Role = "maintainer"

	// RoleBugOwner is the contact for bug reports.
	RoleBugOwner Role = "bugowner"

	// RoleReviewer is a default reviewer of incoming requests.
	RoleReviewer Role = "reviewer"

	// RoleDownloader may download the built binaries.
	RoleDownloader Role = "downloader"

	// RoleReader may read the sources.
	RoleReader Role = "reader"
)

// ReleaseTrigger is the trigger attribute of a release target.
type ReleaseTrigger string

const (
	// ReleaseTriggerManual releases only on an explicit command.
	ReleaseTriggerManual ReleaseTrigger = "manual"

	// ReleaseTriggerMaintenance releases once on a maintenance release event.
	ReleaseTriggerMaintenance ReleaseTrigger = "maintenance"

	// ReleaseTriggerObsGenDiff marks the target used to generate a diff against.
	ReleaseTriggerObsGenDiff ReleaseTrigger = "obsgendiff"
)

// Project is the meta document of an OBS project, limited to the elements
// modeled here.
type Project struct {
	XMLName        xml.Name     `json:"-"                        xml:"project"`
	Name           string       `json:"name"                     xml:"name,attr"`
	Kind           ProjectKind  `json:"kind,omitempty"           xml:"kind,attr,omitempty"`
	Title          string       `json:"title"                    xml:"title"`
	Description    string       `json:"description"              xml:"description"`
	URL            string       `json:"url,omitempty"            xml:"url,omitempty"`
	Persons        []Person     `json:"persons,omitempty"        xml:"person,omitempty"`
	Groups         []Group      `json:"groups,omitempty"         xml:"group,omitempty"`
	Build          Flag         `json:"build,omitempty"          xml:"build,omitempty"`
	Publish        Flag         `json:"publish,omitempty"        xml:"publish,omitempty"`
	UseForBuild    Flag         `json:"useForBuild,omitempty"    xml:"useforbuild,omitempty"`
	DebugInfo      Flag         `json:"debugInfo,omitempty"      xml:"debuginfo,omitempty"`
	BinaryDownload Flag         `json:"binaryDownload,omitempty" xml:"binarydownload,omitempty"`
	Repositories   []Repository `json:"repositories,omitempty"   xml:"repository,omitempty"`
}

// Person assigns a role to an OBS user.
type Person struct {
	UserID string `json:"userid" xml:"userid,attr"`
	Role   Role   `json:"role"   xml:"role,attr"`
}

// Group assigns a role to an OBS group. Groups themselves are managed by the
// OBS instance administrators and cannot be created through this API.
type Group struct {
	GroupID string `json:"groupid" xml:"groupid,attr"`
	Role    Role   `json:"role"    xml:"role,attr"`
}

// Repository is a build target of a project. The order of repositories, of
// their paths and of their architectures is significant to OBS.
type Repository struct {
	Name string `json:"name" xml:"name,attr"`

	// Rebuild is the rebuild policy: transitive, direct or local.
	Rebuild string `json:"rebuild,omitempty" xml:"rebuild,attr,omitempty"`

	// Block is the block policy: all, local or never.
	Block string `json:"block,omitempty" xml:"block,attr,omitempty"`

	// LinkedBuild is the linked build policy: off, localdep, alldirect or all.
	LinkedBuild string `json:"linkedBuild,omitempty" xml:"linkedbuild,attr,omitempty"`

	ReleaseTargets []ReleaseTarget  `json:"releaseTargets,omitempty" xml:"releasetarget,omitempty"`
	Paths          []RepositoryPath `json:"paths,omitempty"          xml:"path,omitempty"`
	Architectures  []string         `json:"architectures,omitempty"  xml:"arch,omitempty"`
}

// ReleaseTarget is the repository that the built binaries are released into.
type ReleaseTarget struct {
	Project    string         `json:"project"           xml:"project,attr"`
	Repository string         `json:"repository"        xml:"repository,attr"`
	Trigger    ReleaseTrigger `json:"trigger,omitempty" xml:"trigger,attr,omitempty"`
}

// RepositoryPath is a repository whose binaries are used to build against.
type RepositoryPath struct {
	Project    string `json:"project"    xml:"project,attr"`
	Repository string `json:"repository" xml:"repository,attr"`
}

// Directory is a listing returned by the OBS source API.
type Directory struct {
	XMLName xml.Name         `json:"-"                 xml:"directory"`
	Count   int              `json:"count,omitempty"   xml:"count,attr,omitempty"`
	Entries []DirectoryEntry `json:"entries,omitempty" xml:"entry"`
}

// DirectoryEntry is a single entry of a Directory.
type DirectoryEntry struct {
	Name string `json:"name" xml:"name,attr"`
}

// ProjectCollection is the result of a project search.
type ProjectCollection struct {
	XMLName  xml.Name    `json:"-"                  xml:"collection"`
	Matches  int         `json:"matches"            xml:"matches,attr"`
	Projects []ProjectID `json:"projects,omitempty" xml:"project"`
}

// ProjectID is a project reference carrying nothing but the project name.
type ProjectID struct {
	Name string `json:"name" xml:"name,attr"`
}

// GetProjectMeta returns the meta of the given project. Use IsNotFound on the
// returned error to check whether the project exists.
func (o *OBS) GetProjectMeta(ctx context.Context, projectName string) (*Project, error) {
	if err := validateProjectName(projectName); err != nil {
		return nil, err
	}

	project := &Project{}
	if err := o.get(ctx, project, nil, "source", projectName, "_meta"); err != nil {
		return nil, fmt.Errorf("getting meta of project %s: %w", projectName, err)
	}

	return project, nil
}

// PutProjectMeta creates the project or updates its meta. OBS replaces the
// whole document, so elements Project does not model are dropped.
func (o *OBS) PutProjectMeta(ctx context.Context, project *Project) error {
	if project == nil {
		return errors.New("project must not be nil")
	}

	if err := validateProjectName(project.Name); err != nil {
		return err
	}

	if err := o.put(ctx, project, "source", project.Name, "_meta"); err != nil {
		return fmt.Errorf("putting meta of project %s: %w", project.Name, err)
	}

	return nil
}

// DeleteProject deletes the given project including all of its packages.
func (o *OBS) DeleteProject(ctx context.Context, projectName string) error {
	if err := validateProjectName(projectName); err != nil {
		return err
	}

	if err := o.delete(ctx, "source", projectName); err != nil {
		return fmt.Errorf("deleting project %s: %w", projectName, err)
	}

	return nil
}

// ListPackages returns the names of all packages of the given project, in the
// order reported by OBS. Release copies are included; use FilterReleaseCopies
// to drop them.
func (o *OBS) ListPackages(ctx context.Context, projectName string) ([]string, error) {
	if err := validateProjectName(projectName); err != nil {
		return nil, err
	}

	directory := &Directory{}
	if err := o.get(ctx, directory, nil, "source", projectName); err != nil {
		return nil, fmt.Errorf("listing packages of project %s: %w", projectName, err)
	}

	packages := make([]string, 0, len(directory.Entries))
	for _, entry := range directory.Entries {
		packages = append(packages, entry.Name)
	}

	return packages, nil
}

// ListSubprojects returns the names of the subprojects of the given project,
// which are the projects whose name starts with the project name followed by a
// colon. The project itself is not among them. The search endpoint requires
// authentication even for public projects.
func (o *OBS) ListSubprojects(ctx context.Context, projectName string) ([]string, error) {
	// The name is interpolated into an XPath string literal. Validation rejects
	// the single quote that would allow breaking out of it.
	if err := validateProjectName(projectName); err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Set("match", fmt.Sprintf("starts-with(@name,'%s:')", projectName))

	collection := &ProjectCollection{}
	if err := o.get(ctx, collection, query, "search", "project", "id"); err != nil {
		return nil, fmt.Errorf("searching for subprojects of %s: %w", projectName, err)
	}

	projects := make([]string, 0, len(collection.Projects))
	for _, project := range collection.Projects {
		projects = append(projects, project.Name)
	}

	return projects, nil
}
