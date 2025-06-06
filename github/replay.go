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

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/go-github/v72/github"
)

func NewReplayer(replayDir string) Client {
	return &githubNotesReplayClient{
		replayDir:   replayDir,
		replayState: map[gitHubAPI]int{},
	}
}

type githubNotesReplayClient struct {
	replayDir   string
	replayMutex sync.Mutex
	replayState map[gitHubAPI]int
}

func (c *githubNotesReplayClient) GetCommit(ctx context.Context, owner, repo, sha string) (*github.Commit, *github.Response, error) { //nolint: revive
	data, err := c.readRecordedData(gitHubAPIGetCommit)
	if err != nil {
		return nil, nil, err
	}

	result := &github.Commit{}

	record := apiRecord{Result: result}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return result, record.response(), nil
}

func (c *githubNotesReplayClient) ListCommits(ctx context.Context, owner, repo string, opt *github.CommitsListOptions) ([]*github.RepositoryCommit, *github.Response, error) { //nolint: revive
	data, err := c.readRecordedData(gitHubAPIListCommits)
	if err != nil {
		return nil, nil, err
	}

	result := []*github.RepositoryCommit{}

	record := apiRecord{Result: &result}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return result, record.response(), nil
}

func (c *githubNotesReplayClient) ListPullRequestsWithCommit(ctx context.Context, owner, repo, sha string, opt *github.ListOptions) ([]*github.PullRequest, *github.Response, error) { //nolint: revive
	data, err := c.readRecordedData(gitHubAPIListPullRequestsWithCommit)
	if err != nil {
		return nil, nil, err
	}

	result := []*github.PullRequest{}

	record := apiRecord{Result: &result}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return result, record.response(), nil
}

func (c *githubNotesReplayClient) GetPullRequest(ctx context.Context, owner, repo string, number int) (*github.PullRequest, *github.Response, error) { //nolint: revive
	data, err := c.readRecordedData(gitHubAPIGetPullRequest)
	if err != nil {
		return nil, nil, err
	}

	result := &github.PullRequest{}

	record := apiRecord{Result: result}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return result, record.response(), nil
}

func (c *githubNotesReplayClient) GetIssue(ctx context.Context, owner, repo string, number int) (*github.Issue, *github.Response, error) { //nolint: revive
	data, err := c.readRecordedData(gitHubAPIGetIssue)
	if err != nil {
		return nil, nil, err
	}

	result := &github.Issue{}

	record := apiRecord{Result: result}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return result, record.response(), nil
}

func (c *githubNotesReplayClient) UpdateIssue(ctx context.Context, owner, repo string, number int, issueRequest *github.IssueRequest) (*github.Issue, *github.Response, error) { //nolint: revive
	data, err := c.readRecordedData(gitHubAPIUpdateIssue)
	if err != nil {
		return nil, nil, err
	}

	result := &github.Issue{}

	record := apiRecord{Result: result}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return result, record.response(), nil
}

func (c *githubNotesReplayClient) AddLabels(ctx context.Context, owner, repo string, number int, labels []string) ([]*github.Label, *github.Response, error) { //nolint: revive
	data, err := c.readRecordedData(gitHubAPIAddLabels)
	if err != nil {
		return nil, nil, err
	}

	result := []*github.Label{}

	record := apiRecord{Result: result}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return result, record.response(), nil
}

func (c *githubNotesReplayClient) GetRepoCommit(ctx context.Context, owner, repo, sha string) (*github.RepositoryCommit, *github.Response, error) { //nolint: revive
	data, err := c.readRecordedData(gitHubAPIGetRepoCommit)
	if err != nil {
		return nil, nil, err
	}

	result := &github.RepositoryCommit{}

	record := apiRecord{Result: result}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return result, record.response(), nil
}

func (c *githubNotesReplayClient) ListReleases(
	ctx context.Context, owner, repo string, opt *github.ListOptions, //nolint: revive
) ([]*github.RepositoryRelease, *github.Response, error) {
	data, err := c.readRecordedData(gitHubAPIListReleases)
	if err != nil {
		return nil, nil, err
	}

	result := []*github.RepositoryRelease{}

	record := apiRecord{Result: result}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return result, record.response(), nil
}

func (c *githubNotesReplayClient) GetReleaseByTag(
	ctx context.Context, owner, repo, tag string, //nolint: revive
) (*github.RepositoryRelease, *github.Response, error) {
	data, err := c.readRecordedData(gitHubAPIGetReleaseByTag)
	if err != nil {
		return nil, nil, err
	}

	result := &github.RepositoryRelease{}

	record := apiRecord{Result: result}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return result, record.response(), nil
}

// TODO: Complete logic.
func (c *githubNotesReplayClient) DownloadReleaseAsset(
	context.Context, string, string, int64,
) (io.ReadCloser, string, error) {
	return nil, "", nil
}

func (c *githubNotesReplayClient) ListTags(
	ctx context.Context, owner, repo string, opt *github.ListOptions, //nolint: revive
) ([]*github.RepositoryTag, *github.Response, error) {
	data, err := c.readRecordedData(gitHubAPIListTags)
	if err != nil {
		return nil, nil, err
	}

	result := []*github.RepositoryTag{}

	record := apiRecord{Result: &result}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return result, record.response(), nil
}

func (c *githubNotesReplayClient) CreatePullRequest(
	ctx context.Context, owner, repo, baseBranchName, headBranchName, title, body string, draft bool, //nolint: revive
) (*github.PullRequest, error) {
	return &github.PullRequest{}, nil
}

func (c *githubNotesReplayClient) RequestPullRequestReview(
	ctx context.Context, owner, repo string, prNumber int, reviewers, teamReviewers []string, //nolint: revive
) (*github.PullRequest, error) {
	return &github.PullRequest{}, nil
}

func (c *githubNotesReplayClient) CreateIssue(
	ctx context.Context, owner, repo string, req *github.IssueRequest, //nolint: revive
) (*github.Issue, error) {
	return &github.Issue{}, nil
}

func (c *githubNotesReplayClient) GetRepository(
	ctx context.Context, owner, repo string, //nolint: revive
) (*github.Repository, *github.Response, error) {
	data, err := c.readRecordedData(gitHubAPIGetRepository)
	if err != nil {
		return nil, nil, err
	}

	repository := &github.Repository{}

	record := apiRecord{Result: repository}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return repository, record.response(), nil
}

func (c *githubNotesReplayClient) ListBranches(
	ctx context.Context, owner, repo string, opts *github.BranchListOptions, //nolint: revive
) ([]*github.Branch, *github.Response, error) {
	data, err := c.readRecordedData(gitHubAPIListBranches)
	if err != nil {
		return nil, nil, err
	}

	branches := make([]*github.Branch, 0)

	record := apiRecord{Result: branches}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return branches, record.response(), nil
}

func (c *githubNotesReplayClient) ListMilestones(
	ctx context.Context, owner, repo string, opts *github.MilestoneListOptions, //nolint: revive
) (mstones []*github.Milestone, resp *github.Response, err error) {
	data, err := c.readRecordedData(gitHubAPIListMilestones)
	if err != nil {
		return nil, nil, err
	}

	mstones = make([]*github.Milestone, 0)

	record := apiRecord{Result: mstones}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return mstones, record.response(), nil
}

func (c *githubNotesReplayClient) readRecordedData(api gitHubAPI) ([]byte, error) {
	c.replayMutex.Lock()
	defer c.replayMutex.Unlock()

	i := 0
	if j, ok := c.replayState[api]; ok {
		i = j
	}

	path := filepath.Join(c.replayDir, fmt.Sprintf("%s-%d.json", api, i))

	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	c.replayState[api]++

	return file, nil
}

// UpdateReleasePage modifies a release, not recorded.
func (c *githubNotesReplayClient) UpdateReleasePage(
	ctx context.Context, owner, repo string, releaseID int64, releaseData *github.RepositoryRelease, //nolint: revive
) (*github.RepositoryRelease, error) {
	return &github.RepositoryRelease{}, nil
}

// UploadReleaseAsset uploads files, not recorded.
func (c *githubNotesReplayClient) UploadReleaseAsset(
	context.Context, string, string, int64, *github.UploadOptions, *os.File,
) (*github.ReleaseAsset, error) {
	return &github.ReleaseAsset{}, nil
}

// DeleteReleaseAsset removes an asset from a page, note recorded.
func (c *githubNotesReplayClient) DeleteReleaseAsset(
	ctx context.Context, owner, repo string, assetID int64, //nolint: revive
) error {
	return nil
}

func (c *githubNotesReplayClient) ListReleaseAssets(
	ctx context.Context, owner, repo string, releaseID int64, opts *github.ListOptions, //nolint: revive
) ([]*github.ReleaseAsset, error) {
	data, err := c.readRecordedData(gitHubAPIListReleaseAssets)
	if err != nil {
		return nil, err
	}

	assets := make([]*github.ReleaseAsset, 0)

	record := apiRecord{Result: assets}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}

	return assets, nil
}

func (c *githubNotesReplayClient) CreateComment(ctx context.Context, owner, repo string, number int, message string) (*github.IssueComment, *github.Response, error) { //nolint: revive
	data, err := c.readRecordedData(gitHubAPICreateComment)
	if err != nil {
		return nil, nil, err
	}

	result := &github.IssueComment{}

	record := apiRecord{Result: result}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return result, record.response(), nil
}

func (c *githubNotesReplayClient) ListIssues(
	_ context.Context, owner, repo string, opts *github.IssueListByRepoOptions, //nolint: revive
) ([]*github.Issue, *github.Response, error) {
	data, err := c.readRecordedData(gitHubAPIListIssues)
	if err != nil {
		return nil, nil, err
	}

	issues := make([]*github.Issue, 0)

	record := apiRecord{Result: issues}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return issues, record.response(), nil
}

func (c *githubNotesReplayClient) ListComments(
	_ context.Context, owner, repo string, number int, opts *github.IssueListCommentsOptions, //nolint: revive
) ([]*github.IssueComment, *github.Response, error) {
	data, err := c.readRecordedData(gitHubAPIListComments)
	if err != nil {
		return nil, nil, err
	}

	comments := make([]*github.IssueComment, 0)

	record := apiRecord{Result: comments}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return comments, record.response(), nil
}

func (c *githubNotesReplayClient) CheckRateLimit(
	_ context.Context,
) (*github.RateLimits, *github.Response, error) {
	data, err := c.readRecordedData(gitHubAPICheckRateLimit)
	if err != nil {
		return nil, nil, err
	}

	rt := &github.RateLimits{}

	record := apiRecord{Result: rt}
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, nil, err
	}

	return rt, record.response(), nil
}
