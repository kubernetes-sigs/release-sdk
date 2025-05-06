/*
Copyright 2020 The Kubernetes Authors.

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

package github_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	gogithub "github.com/google/go-github/v60/github"
	"github.com/stretchr/testify/require"

	"k8s.io/utils/ptr"

	"sigs.k8s.io/release-sdk/git"
	"sigs.k8s.io/release-sdk/github"
	"sigs.k8s.io/release-sdk/github/githubfakes"
)

func newSUT() (*github.GitHub, *githubfakes.FakeClient) {
	client := &githubfakes.FakeClient{}
	sut := github.New()
	sut.SetClient(client)

	return sut, client
}

func TestLatestGitHubTagsPerBranchSuccessEmptyResult(t *testing.T) {
	// Given
	sut, client := newSUT()
	client.ListTagsReturns(nil, &gogithub.Response{NextPage: 0}, nil)

	// When
	res, err := sut.LatestGitHubTagsPerBranch()

	// Then
	require.NoError(t, err)
	require.Empty(t, res)
}

func TestLatestGitHubTagsPerBranchSuccessAlphaAfterMinor(t *testing.T) {
	// Given
	var (
		tag1 = "v1.18.0-alpha.2"
		tag2 = "v1.18.0"
	)

	sut, client := newSUT()
	client.ListTagsReturns([]*gogithub.RepositoryTag{
		{Name: &tag1},
		{Name: &tag2},
	}, &gogithub.Response{NextPage: 0}, nil)

	// When
	res, err := sut.LatestGitHubTagsPerBranch()

	// Then
	require.NoError(t, err)
	require.Len(t, res, 2)
	require.Equal(t, tag1, res[git.DefaultBranch])
	require.Equal(t, tag2, res["release-1.18"])
}

func TestLatestGitHubTagsPerBranchMultiplePages(t *testing.T) {
	// Given
	var (
		tag1 = "v1.18.0-alpha.2"
		tag2 = "v1.18.0"
	)

	sut, client := newSUT()
	client.ListTagsReturnsOnCall(0, []*gogithub.RepositoryTag{
		{Name: &tag1},
	}, &gogithub.Response{NextPage: 1}, nil)
	client.ListTagsReturnsOnCall(1, []*gogithub.RepositoryTag{
		{Name: &tag2},
	}, &gogithub.Response{NextPage: 0}, nil)

	// When
	res, err := sut.LatestGitHubTagsPerBranch()

	// Then
	require.NoError(t, err)
	require.Len(t, res, 2)
	require.Equal(t, tag1, res[git.DefaultBranch])
	require.Equal(t, tag2, res["release-1.18"])
}

func TestLatestGitHubTagsPerBranchSuccessMultipleForSameBranch(t *testing.T) {
	// Given
	var (
		tag1 = "v1.18.0-beta.0"
		tag2 = "v1.18.0-alpha.3"
		tag3 = "v1.15.2"
		tag4 = "v1.18.0-alpha.2"
		tag5 = "v1.16.3"
		tag6 = "v1.18.0-alpha.1"
		tag7 = "v1.13.0"
		tag8 = "v1.18.0-alpha.2"
	)

	sut, client := newSUT()
	client.ListTagsReturns([]*gogithub.RepositoryTag{
		{Name: &tag1},
		{Name: &tag2},
		{Name: &tag3},
		{Name: &tag4},
		{Name: &tag5},
		{Name: &tag6},
		{Name: &tag7},
		{Name: &tag8},
	}, &gogithub.Response{NextPage: 0}, nil)

	// When
	res, err := sut.LatestGitHubTagsPerBranch()

	// Then
	require.NoError(t, err)
	require.Len(t, res, 4)
	require.Equal(t, tag1, res[git.DefaultBranch])
	require.Empty(t, res["release-1.18"])
	require.Empty(t, res["release-1.17"])
	require.Equal(t, tag5, res["release-1.16"])
	require.Equal(t, tag3, res["release-1.15"])
	require.Empty(t, res["release-1.14"])
	require.Equal(t, tag7, res["release-1.13"])
}

func TestLatestGitHubTagsPerBranchSuccessPatchReleases(t *testing.T) {
	// Given
	var (
		tag1 = "v1.17.1"
		tag2 = "v1.16.2"
		tag3 = "v1.15.3"
	)

	sut, client := newSUT()
	client.ListTagsReturns([]*gogithub.RepositoryTag{
		{Name: &tag1},
		{Name: &tag2},
		{Name: &tag3},
	}, &gogithub.Response{NextPage: 0}, nil)

	// When
	res, err := sut.LatestGitHubTagsPerBranch()

	// Then
	require.NoError(t, err)
	require.Len(t, res, 4)
	require.Equal(t, tag1, res[git.DefaultBranch])
	require.Equal(t, tag1, res["release-1.17"])
	require.Equal(t, tag2, res["release-1.16"])
	require.Equal(t, tag3, res["release-1.15"])
	require.Empty(t, res["release-1.18"])
}

func TestLatestGitHubTagsPerBranchFailedOnList(t *testing.T) {
	// Given
	sut, client := newSUT()
	client.ListTagsReturns(nil, nil, errors.New("error"))

	// When
	res, err := sut.LatestGitHubTagsPerBranch()

	// Then
	require.Error(t, err)
	require.Nil(t, res)
}

func TestLatestGitHubTagsPerBranchSkippedNonSemverTag(t *testing.T) {
	// Given
	tag1 := "not a semver tag"
	sut, client := newSUT()
	client.ListTagsReturns([]*gogithub.RepositoryTag{
		{Name: &tag1},
	}, &gogithub.Response{NextPage: 0}, nil)

	// When
	res, err := sut.LatestGitHubTagsPerBranch()

	// Then
	require.NoError(t, err)
	require.Empty(t, res)
}

func TestReleasesSuccessEmpty(t *testing.T) {
	// Given
	sut, client := newSUT()
	client.ListReleasesReturns([]*gogithub.RepositoryRelease{}, nil, nil)

	// When
	res, err := sut.Releases("", "", false)

	// Then
	require.NoError(t, err)
	require.Empty(t, res)
}

func TestReleasesSuccessNoPreReleases(t *testing.T) {
	// Given
	var (
		tag1  = "v1.18.0"
		tag2  = "v1.17.0"
		tag3  = "v1.16.0"
		tag4  = "v1.15.0"
		aTrue = true
	)

	sut, client := newSUT()
	client.ListReleasesReturns([]*gogithub.RepositoryRelease{
		{TagName: &tag1},
		{TagName: &tag2},
		{TagName: &tag3, Prerelease: &aTrue},
		{TagName: &tag4},
	}, nil, nil)

	// When
	res, err := sut.Releases("", "", false)

	// Then
	require.NoError(t, err)
	require.Len(t, res, 3)
	require.Equal(t, tag1, res[0].GetTagName())
	require.Equal(t, tag2, res[1].GetTagName())
	require.Equal(t, tag4, res[2].GetTagName())
}

func TestReleasesSuccessWithPreReleases(t *testing.T) {
	// Given
	var (
		tag1  = "v1.18.0"
		tag2  = "v1.17.0"
		tag3  = "v1.16.0"
		tag4  = "v1.15.0"
		aTrue = true
	)

	sut, client := newSUT()
	client.ListReleasesReturns([]*gogithub.RepositoryRelease{
		{TagName: &tag1},
		{TagName: &tag2, Prerelease: &aTrue},
		{TagName: &tag3, Prerelease: &aTrue},
		{TagName: &tag4},
	}, nil, nil)

	// When
	res, err := sut.Releases("", "", true)

	// Then
	require.NoError(t, err)
	require.Len(t, res, 4)
	require.Equal(t, tag1, res[0].GetTagName())
	require.Equal(t, tag2, res[1].GetTagName())
	require.Equal(t, tag3, res[2].GetTagName())
	require.Equal(t, tag4, res[3].GetTagName())
}

func TestReleasesFailed(t *testing.T) {
	// Given
	sut, client := newSUT()
	client.ListReleasesReturns(nil, nil, errors.New("error"))

	// When
	res, err := sut.Releases("", "", false)

	// Then
	require.Error(t, err)
	require.Nil(t, res, nil)
}

func TestCreatePullRequest(t *testing.T) {
	// Given
	sut, client := newSUT()
	fakeID := int64(1234)
	client.CreatePullRequestReturns(&gogithub.PullRequest{ID: &fakeID}, nil)

	// When
	pr, err := sut.CreatePullRequest("kubernetes-fake-org", "kubernetes-fake-repo", git.DefaultBranch, "user:head-branch", "PR Title", "PR Body", false)

	// Then
	require.NoError(t, err)
	require.NotNil(t, pr, nil)
	require.Equal(t, fakeID, pr.GetID())
}

func TestRequestReviewers(t *testing.T) {
	// Given
	sut, client := newSUT()
	fakeID := int64(1234)
	fakeNumber := int(5678)
	fakeUser := "fakeuser"
	client.RequestPullRequestReviewReturns(&gogithub.PullRequest{
		ID:     &fakeID,
		Number: &fakeNumber,
		RequestedReviewers: []*gogithub.User{
			{
				Login: &fakeUser,
				Name:  &fakeUser,
			},
		},
	}, nil)

	// When requesting reviewers
	updatedPr, err := sut.RequestPullRequestReview("kubernetes-fake-org", "kubernetes-fake-repo", fakeNumber, []string{fakeUser}, []string{})
	require.NoError(t, err)
	require.NotNil(t, updatedPr, nil)
	require.Equal(t, fakeID, updatedPr.GetID())
	require.Equal(t, fakeNumber, updatedPr.GetNumber())
	require.Len(t, updatedPr.RequestedReviewers, 1)
	require.Equal(t, fakeUser, updatedPr.RequestedReviewers[0].GetName())
}

func TestGetMilestone(t *testing.T) {
	sut, client := newSUT()
	// Given
	searchTitle := "Target Milestone"
	otherTitle := "Another Milestone"
	fakeMstoneID := 9999

	client.ListMilestonesReturns(
		[]*gogithub.Milestone{
			{
				Title: &otherTitle,
			},
			{
				Number: &fakeMstoneID,
				Title:  &searchTitle,
			},
		},
		&gogithub.Response{NextPage: 0},
		nil,
	)

	// When
	for _, tc := range []struct {
		Title string
		Err   bool
	}{
		{Title: searchTitle},
		{Title: "Non existent"},
		{Title: "", Err: true},
	} {
		ms, exists, err := sut.GetMilestone("test", "test", tc.Title)

		// Then
		if searchTitle == tc.Title {
			require.True(t, exists)
			require.Equal(t, fakeMstoneID, ms.GetNumber())
			require.Equal(t, searchTitle, ms.GetTitle())
		} else {
			require.False(t, exists)
		}

		if tc.Err {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestGetRepository(t *testing.T) {
	// Given
	sut, client := newSUT()
	fakeRepositoryID := int64(54596517) // k/release
	kubernetesUserID := int64(13629408)
	kubernetesLogin := "kubernetes"
	repoName := "release"
	client.GetRepositoryReturns(&gogithub.Repository{
		ID:   &fakeRepositoryID,
		Name: &repoName,
		Owner: &gogithub.User{
			Login: &kubernetesLogin,
			ID:    &kubernetesUserID,
		},
	}, &gogithub.Response{NextPage: 0}, nil)

	// When
	repo, err := sut.GetRepository("kubernetes", "release")

	// Then
	require.NoError(t, err)
	require.NotNil(t, repo, nil)
	require.Equal(t, fakeRepositoryID, repo.GetID())
	require.Equal(t, kubernetesUserID, repo.GetOwner().GetID())
	require.Equal(t, kubernetesLogin, repo.GetOwner().GetLogin())
	require.Equal(t, repoName, repo.GetName())
}

func TestRepoIsForkOf(t *testing.T) {
	// Given
	sut, client := newSUT()

	forkOwner := "fork"
	parentOwner := "kubernetes"
	repoName := "forkedRepo"

	parentFullName := fmt.Sprintf("%s/%s", parentOwner, repoName)

	trueVal := true

	client.GetRepositoryReturns(&gogithub.Repository{
		Name: &repoName,
		Fork: &trueVal,
		Owner: &gogithub.User{
			Login: &forkOwner,
		},
		Parent: &gogithub.Repository{
			Name: &repoName,
			Owner: &gogithub.User{
				Login: &parentOwner,
			},
			FullName: &parentFullName,
		},
	}, &gogithub.Response{NextPage: 0}, nil)

	// When
	result, err := sut.RepoIsForkOf("fork", repoName, "kubernetes", repoName)

	// Then
	require.NoError(t, err)
	require.True(t, result)
}

func TestRepoIsNotForkOf(t *testing.T) {
	// Given
	sut, client := newSUT()

	forkOwner := "fork"
	parentOwner := "borg"
	repoName := "notForkedRepo"

	parentFullName := fmt.Sprintf("%s/%s", parentOwner, repoName)

	trueVal := true

	client.GetRepositoryReturns(&gogithub.Repository{
		Name: &repoName,
		Fork: &trueVal,
		Owner: &gogithub.User{
			Login: &forkOwner,
		},
		Parent: &gogithub.Repository{
			Name: &repoName,
			Owner: &gogithub.User{
				Login: &parentOwner,
			},
			FullName: &parentFullName,
		},
	}, &gogithub.Response{NextPage: 0}, nil)

	// When
	result, err := sut.RepoIsForkOf("fork", repoName, "kubernetes", repoName)

	// Then
	require.NoError(t, err)
	require.False(t, result)
}

func TestListBranches(t *testing.T) {
	// Given
	sut, client := newSUT()

	branch0 := git.DefaultBranch
	branch1 := "myfork"
	branch2 := "feature-branch"

	branches := []*gogithub.Branch{
		{
			Name: &branch0,
		},
		{
			Name: &branch1,
		},
		{
			Name: &branch2,
		},
	}

	client.ListBranchesReturns(branches, &gogithub.Response{NextPage: 0}, nil)

	// When
	result, err := sut.ListBranches("kubernetes", "kubernotia")

	// Then
	require.NoError(t, err)
	require.Len(t, result, 3)
	require.Equal(t, result[1].GetName(), branch1)
}

func TestCreateIssue(t *testing.T) {
	// Given
	sut, client := newSUT()
	fakeID := 100000
	title := "Test Issue"
	body := "Issue body text"
	opts := &github.NewIssueOptions{
		Assignees: []string{"k8s-ci-robot"},
		Milestone: "v1.21",
		State:     "open",
		Labels:    []string{"bug"},
	}
	issue := &gogithub.Issue{
		Number: &fakeID,
		State:  &opts.State,
		Title:  &title,
		Body:   &body,
	}

	for _, tcErr := range []error{errors.New("Test error"), nil} {
		// When
		client.CreateIssueReturns(issue, tcErr)

		newissue, err := sut.CreateIssue("kubernetes-fake-org", "kubernetes-fake-repo", title, body, opts)

		// Then
		if tcErr == nil {
			require.NoError(t, err)
			require.NotNil(t, newissue)
			require.Equal(t, fakeID, issue.GetNumber())
		} else {
			require.Error(t, err)
		}
	}
}

func TestUpdateIssue(t *testing.T) {
	// Given
	sut, client := newSUT()
	fakeID := 100000
	title := "Test Issue"
	body := "Issue body text"
	opts := &github.NewIssueOptions{
		Assignees: []string{"k8s-ci-robot"},
		Milestone: "v1.21",
		State:     "open",
		Labels:    []string{"bug"},
	}
	issue := &gogithub.Issue{
		Number: &fakeID,
		State:  &opts.State,
		Title:  &title,
		Body:   &body,
	}

	updatedtitle := "Test Issue updated"
	updatedopts := &github.NewIssueOptions{
		State: "closed",
	}
	updatedIssue := &gogithub.Issue{
		Number: &fakeID,
		State:  &updatedopts.State,
		Title:  &updatedtitle,
		Body:   &body,
	}

	issueRequest := &gogithub.IssueRequest{}

	for _, tcErr := range []error{errors.New("Test error"), nil} {
		// When
		client.CreateIssueReturns(issue, tcErr)

		newissue, err := sut.CreateIssue("kubernetes-fake-org", "kubernetes-fake-repo", title, body, opts)
		if tcErr == nil {
			require.NoError(t, err)
			require.NotNil(t, newissue)
			require.Equal(t, fakeID, issue.GetNumber())
		} else {
			require.Error(t, err)
		}

		client.UpdateIssueReturns(updatedIssue, nil, tcErr)
		updatedIssue, _, err := client.UpdateIssue(t.Context(), "kubernetes-fake-org", "kubernetes-fake-repo", newissue.GetNumber(), issueRequest)

		// Then
		if tcErr == nil {
			require.NoError(t, err)
			require.NotNil(t, updatedIssue)
			require.Equal(t, updatedopts.State, updatedIssue.GetState())
		} else {
			require.Error(t, err)
		}
	}
}

func TestAddLabels(t *testing.T) {
	// Given
	_, client := newSUT()
	label := "honk-label"

	labelToAdd := []*gogithub.Label{
		{
			Name: &label,
		},
	}

	for _, tcErr := range []error{errors.New("Test error"), nil} {
		// When
		client.AddLabelsReturns(labelToAdd, nil, tcErr)
		updatedLabel, _, err := client.AddLabels(t.Context(), "kubernetes-fake-org", "kubernetes-fake-repo", 1234, []string{"honk-label"})

		// Then
		if tcErr == nil {
			require.NoError(t, err)
			require.NotNil(t, updatedLabel)
			require.Equal(t, labelToAdd, updatedLabel)
		} else {
			require.Error(t, err)
		}
	}
}

func TestListIssues(t *testing.T) {
	// Given
	sut, client := newSUT()

	issue0 := "My title 1"
	issue1 := "Create XYZ"
	issue2 := "foo-bar"

	issues := []*gogithub.Issue{
		{Title: &issue0},
		{Title: &issue1},
		{Title: &issue2},
	}

	client.ListIssuesReturns(issues, &gogithub.Response{NextPage: 0}, nil)

	// When
	result, err := sut.ListIssues("kubernetes", "kubernotia", github.IssueStateOpen)

	// Then
	require.NoError(t, err)
	require.Len(t, result, 3)
	require.Equal(t, result[0].GetTitle(), issue0)
	require.Equal(t, result[1].GetTitle(), issue1)
	require.Equal(t, result[2].GetTitle(), issue2)
}

func TestListComments(t *testing.T) {
	// Given
	sut, client := newSUT()

	comment0 := "comment 0"
	comment1 := "comment 1"
	comment2 := "comment 2"

	comments := []*gogithub.IssueComment{
		{Body: &comment0},
		{Body: &comment1},
		{Body: &comment2},
	}

	client.ListCommentsReturns(comments, &gogithub.Response{NextPage: 0}, nil)

	since := time.Now()

	// When
	result, err := sut.ListComments(
		"fake-owner",
		"fake-repo",
		1,
		github.SortCreated,
		github.SortDirectionAscending,
		&since,
	)

	// Then
	require.NoError(t, err)
	require.Len(t, result, 3)
	require.Equal(t, result[0].GetBody(), comment0)
	require.Equal(t, result[1].GetBody(), comment1)
	require.Equal(t, result[2].GetBody(), comment2)
}

func TestUpdateReleasePageWithOptions(t *testing.T) {
	// Given
	sut, client := newSUT()
	fakeID := int64(100000)
	tagName := "v0.0.1"
	commitish := "fakefake"
	name := "v0.0.1"
	body := "Fake Release Body"
	opts := &github.UpdateReleasePageOptions{
		Name:       &name,
		Body:       &body,
		Draft:      ptr.To(false),
		Prerelease: ptr.To(false),
		Latest:     ptr.To(true),
	}
	release := &gogithub.RepositoryRelease{
		ID:              &fakeID,
		Name:            &name,
		Body:            &body,
		TagName:         &tagName,
		TargetCommitish: &commitish,

		Draft:      ptr.To(false),
		Prerelease: ptr.To(false),
		MakeLatest: ptr.To("true"),
	}

	for _, tcErr := range []error{errors.New("Test error"), nil} {
		// When
		client.UpdateReleasePageReturns(release, tcErr)

		releaseData, err := sut.UpdateReleasePageWithOptions("kubernetes-fake-org", "kubernetes-fake-repo", 0, tagName, commitish, opts)

		// Then
		if tcErr == nil {
			require.NoError(t, err)
			require.NotNil(t, releaseData)
			require.Equal(t, fakeID, releaseData.GetID())
			require.Equal(t, commitish, releaseData.GetTargetCommitish())
			require.Equal(t, name, releaseData.GetName())
			require.Equal(t, body, releaseData.GetBody())
			require.False(t, release.GetDraft())
			require.False(t, release.GetPrerelease())
			require.Equal(t, "true", release.GetMakeLatest())
		} else {
			require.Error(t, err)
		}
	}
}

func TestCheckRateLimit(t *testing.T) {
	// Given
	sut, client := newSUT()

	now := gogithub.Timestamp{time.Now().UTC()} //nolint: govet

	rt := &gogithub.RateLimits{
		Core: &gogithub.Rate{
			Limit:     5000,
			Remaining: 200,
			Reset:     now,
		},
	}

	client.CheckRateLimitReturns(rt, &gogithub.Response{}, nil)

	// When
	rt, result, err := sut.CheckRateLimit(t.Context())

	// Then
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, 5000, rt.Core.Limit)
	require.Equal(t, 200, rt.Core.Remaining)
	require.Equal(t, rt.Core.Reset, now)
}
