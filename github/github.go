/*
Copyright 2021 The Kubernetes Authors.

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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-github/v72/github"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"k8s.io/utils/ptr"

	"sigs.k8s.io/release-utils/env"
	"sigs.k8s.io/release-utils/util"

	"sigs.k8s.io/release-sdk/git"
	ghinternal "sigs.k8s.io/release-sdk/github/internal"
)

const (
	// TokenEnvKey is the default GitHub token environment variable key.
	TokenEnvKey = "GITHUB_TOKEN"
	// GitHubURL Prefix for github URLs.
	GitHubURL = "https://github.com/"

	unauthenticated = "unauthenticated"
)

// GitHub is a wrapper around GitHub related functionality.
type GitHub struct {
	client  Client
	options *Options
}

type githubClient struct {
	*github.Client
}

// Options is a set of options to configure the behavior of the GitHub package.
type Options struct {
	// How many items to request in calls to the github API
	// that require pagination.
	ItemsPerPage int
}

func (o *Options) GetItemsPerPage() int {
	return o.ItemsPerPage
}

// DefaultOptions return an options struct with commonly used settings.
func DefaultOptions() *Options {
	return &Options{
		ItemsPerPage: 50,
	}
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . Client
//go:generate /usr/bin/env bash -c "cat ../scripts/boilerplate/boilerplate.generatego.txt githubfakes/fake_client.go > githubfakes/_fake_client.go && mv githubfakes/_fake_client.go githubfakes/fake_client.go"

// Client is an interface modeling supported GitHub operations.
type Client interface {
	GetCommit(
		context.Context, string, string, string,
	) (*github.Commit, *github.Response, error)
	GetPullRequest(
		context.Context, string, string, int,
	) (*github.PullRequest, *github.Response, error)
	GetIssue(
		context.Context, string, string, int,
	) (*github.Issue, *github.Response, error)
	GetRepoCommit(
		context.Context, string, string, string,
	) (*github.RepositoryCommit, *github.Response, error)
	ListCommits(
		context.Context, string, string, *github.CommitsListOptions,
	) ([]*github.RepositoryCommit, *github.Response, error)
	ListPullRequestsWithCommit(
		context.Context, string, string, string, *github.ListOptions,
	) ([]*github.PullRequest, *github.Response, error)
	ListMilestones(
		context.Context, string, string, *github.MilestoneListOptions,
	) ([]*github.Milestone, *github.Response, error)
	ListReleases(
		context.Context, string, string, *github.ListOptions,
	) ([]*github.RepositoryRelease, *github.Response, error)
	GetReleaseByTag(
		context.Context, string, string, string,
	) (*github.RepositoryRelease, *github.Response, error)
	DownloadReleaseAsset(
		context.Context, string, string, int64,
	) (io.ReadCloser, string, error)
	ListTags(
		context.Context, string, string, *github.ListOptions,
	) ([]*github.RepositoryTag, *github.Response, error)
	ListBranches(
		context.Context, string, string, *github.BranchListOptions,
	) ([]*github.Branch, *github.Response, error)
	CreatePullRequest(
		context.Context, string, string, string, string, string, string, bool,
	) (*github.PullRequest, error)
	CreateIssue(
		context.Context, string, string, *github.IssueRequest,
	) (*github.Issue, error)
	GetRepository(
		context.Context, string, string,
	) (*github.Repository, *github.Response, error)
	UpdateReleasePage(
		context.Context, string, string, int64, *github.RepositoryRelease,
	) (*github.RepositoryRelease, error)
	UpdateIssue(
		context.Context, string, string, int, *github.IssueRequest,
	) (*github.Issue, *github.Response, error)
	AddLabels(
		context.Context, string, string, int, []string,
	) ([]*github.Label, *github.Response, error)
	UploadReleaseAsset(
		context.Context, string, string, int64, *github.UploadOptions, *os.File,
	) (*github.ReleaseAsset, error)
	DeleteReleaseAsset(
		context.Context, string, string, int64,
	) error
	ListReleaseAssets(
		context.Context, string, string, int64, *github.ListOptions,
	) ([]*github.ReleaseAsset, error)
	CreateComment(
		context.Context, string, string, int, string,
	) (*github.IssueComment, *github.Response, error)
	ListIssues(
		context.Context, string, string, *github.IssueListByRepoOptions,
	) ([]*github.Issue, *github.Response, error)
	ListComments(
		context.Context, string, string, int, *github.IssueListCommentsOptions,
	) ([]*github.IssueComment, *github.Response, error)
	RequestPullRequestReview(
		context.Context, string, string, int, []string, []string,
	) (*github.PullRequest, error)
	CheckRateLimit(
		context.Context,
	) (*github.RateLimits, *github.Response, error)
}

// NewIssueOptions is a struct of optional fields for new issues.
type NewIssueOptions struct {
	Milestone string   // Name of milestone to set
	State     string   // open, closed or all. Defaults to "open"
	Assignees []string // List of GitHub handles of extra assignees, must be collaborators
	Labels    []string // List of labels to apply. They will be created if new
}

// UpdateReleasePageOptions is a struct of optional fields for creating/updating releases.
type UpdateReleasePageOptions struct {
	// Name is the name/title of the release.
	Name *string
	// Body is the body/content of the release (e.g. release notes).
	Body *string
	// Draft is marking the release as draft, if set to true.
	Draft *bool
	// Prerelease is marking the release as a pre-release, if set to true.
	Prerelease *bool
	// Latest is marking the release to be set as latest at the time of updating, if set to true.
	Latest *bool
}

// TODO: we should clean up the functions listed below and agree on the same
// return type (with or without error):
// - New
// - NewWithToken
// - NewEnterprise
// - NewEnterpriseWithToken

// New creates a new default GitHub client. Tokens set via the $GITHUB_TOKEN
// environment variable will result in an authenticated client.
// If the $GITHUB_TOKEN is not set, then the client will do unauthenticated
// GitHub requests.
func New() *GitHub {
	token := env.Default(TokenEnvKey, "")
	client, _ := NewWithToken(token)

	return client
}

// NewWithToken can be used to specify a GitHub token through parameters.
// Empty string will result in unauthenticated client, which makes
// unauthenticated requests.
func NewWithToken(token string) (*GitHub, error) {
	ctx := context.Background()
	client := http.DefaultClient

	state := unauthenticated
	if token != "" {
		state = strings.TrimPrefix(state, "un")
		client = oauth2.NewClient(ctx, oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		))
	}

	logrus.Debugf("Using %s GitHub client", state)

	return &GitHub{
		client:  &githubClient{github.NewClient(client)},
		options: DefaultOptions(),
	}, nil
}

// NewWithTokenWithClient can be used to specify a GitHub token through parameters and
// set an custom HTTP Client.
// Empty string will result in unauthenticated client, which makes
// unauthenticated requests.
func NewWithTokenWithClient(token string, httpClient *http.Client) (*GitHub, error) {
	client := httpClient

	state := unauthenticated
	if token != "" {
		state = strings.TrimPrefix(state, "un")
		// Set the Transport of the existing httpClient to include the OAuth2 transport
		if client == nil {
			client = &http.Client{}
		}

		client.Transport = &oauth2.Transport{
			Source: oauth2.StaticTokenSource(
				&oauth2.Token{AccessToken: token},
			),
			Base: client.Transport, // Preserve the original transport
		}
	}

	logrus.Debugf("Using %s GitHub client", state)

	return &GitHub{
		client:  &githubClient{github.NewClient(client)},
		options: DefaultOptions(),
	}, nil
}

func NewEnterprise(baseURL, uploadURL string) (*GitHub, error) {
	token := env.Default(TokenEnvKey, "")

	return NewEnterpriseWithToken(baseURL, uploadURL, token)
}

func NewEnterpriseWithToken(baseURL, uploadURL, token string) (*GitHub, error) {
	ctx := context.Background()
	client := http.DefaultClient

	state := unauthenticated
	if token != "" {
		state = strings.TrimPrefix(state, "un")
		client = oauth2.NewClient(ctx, oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		))
	}

	logrus.Debugf("Using %s Enterprise GitHub client", state)

	ghclient, err := github.NewClient(client).WithEnterpriseURLs(baseURL, uploadURL)
	if err != nil {
		return nil, fmt.Errorf("failed to new github client: %w", err)
	}

	return &GitHub{
		client:  &githubClient{ghclient},
		options: DefaultOptions(),
	}, nil
}

func (g *githubClient) GetCommit(
	ctx context.Context, owner, repo, sha string,
) (*github.Commit, *github.Response, error) {
	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		commit, resp, err := g.Git.GetCommit(ctx, owner, repo, sha)
		if !shouldRetry(err) {
			return commit, resp, err
		}
	}
}

func (g *githubClient) GetPullRequest(
	ctx context.Context, owner, repo string, number int,
) (*github.PullRequest, *github.Response, error) {
	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		pr, resp, err := g.PullRequests.Get(ctx, owner, repo, number)
		if !shouldRetry(err) {
			return pr, resp, err
		}
	}
}

func (g *githubClient) GetIssue(
	ctx context.Context, owner, repo string, number int,
) (*github.Issue, *github.Response, error) {
	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		issue, resp, err := g.Issues.Get(ctx, owner, repo, number)
		if !shouldRetry(err) {
			return issue, resp, err
		}
	}
}

func (g *githubClient) GetRepoCommit(
	ctx context.Context, owner, repo, sha string,
) (*github.RepositoryCommit, *github.Response, error) {
	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		commit, resp, err := g.Repositories.GetCommit(ctx, owner, repo, sha, nil)
		if !shouldRetry(err) {
			return commit, resp, err
		}
	}
}

func (g *githubClient) ListCommits(
	ctx context.Context, owner, repo string, opt *github.CommitsListOptions,
) ([]*github.RepositoryCommit, *github.Response, error) {
	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		commits, resp, err := g.Repositories.ListCommits(ctx, owner, repo, opt)
		if !shouldRetry(err) {
			return commits, resp, err
		}
	}
}

func (g *githubClient) ListPullRequestsWithCommit(
	ctx context.Context, owner, repo, sha string,
	opt *github.ListOptions,
) ([]*github.PullRequest, *github.Response, error) {
	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		prs, resp, err := g.PullRequests.ListPullRequestsWithCommit(
			ctx, owner, repo, sha, opt,
		)
		if !shouldRetry(err) {
			return prs, resp, err
		}
	}
}

func (g *githubClient) ListReleases(
	ctx context.Context, owner, repo string, opt *github.ListOptions,
) ([]*github.RepositoryRelease, *github.Response, error) {
	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		releases, resp, err := g.Repositories.ListReleases(
			ctx, owner, repo, opt,
		)
		if !shouldRetry(err) {
			return releases, resp, err
		}
	}
}

func (g *githubClient) GetReleaseByTag(
	ctx context.Context, owner, repo, tag string,
) (*github.RepositoryRelease, *github.Response, error) {
	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		release, resp, err := g.Repositories.GetReleaseByTag(ctx, owner, repo, tag)
		if !shouldRetry(err) {
			return release, resp, err
		}
	}
}

func (g *githubClient) DownloadReleaseAsset(
	ctx context.Context, owner, repo string, assetID int64,
) (io.ReadCloser, string, error) {
	// TODO: Should we be getting this http client from somewhere else?
	httpClient := http.DefaultClient

	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		assetBody, redirectURL, err := g.Repositories.DownloadReleaseAsset(ctx, owner, repo, assetID, httpClient)
		if !shouldRetry(err) {
			return assetBody, redirectURL, err
		}
	}
}

func (g *githubClient) ListTags(
	ctx context.Context, owner, repo string, opt *github.ListOptions,
) ([]*github.RepositoryTag, *github.Response, error) {
	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		tags, resp, err := g.Repositories.ListTags(ctx, owner, repo, opt)
		if !shouldRetry(err) {
			return tags, resp, err
		}
	}
}

func (g *githubClient) ListBranches(
	ctx context.Context, owner, repo string, opt *github.BranchListOptions,
) ([]*github.Branch, *github.Response, error) {
	branches, response, err := g.Repositories.ListBranches(ctx, owner, repo, opt)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching branches from repo: %w", err)
	}

	return branches, response, nil
}

// ListMilestones calls the github API to retrieve milestones (with retry).
func (g *githubClient) ListMilestones(
	ctx context.Context, owner, repo string, opts *github.MilestoneListOptions,
) (mstones []*github.Milestone, resp *github.Response, err error) {
	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		mstones, resp, err := g.Issues.ListMilestones(ctx, owner, repo, opts)
		if !shouldRetry(err) {
			return mstones, resp, err
		}
	}
}

func (g *githubClient) CreatePullRequest(
	ctx context.Context, owner, repo, baseBranchName, headBranchName, title, body string, draft bool,
) (*github.PullRequest, error) {
	newPullRequest := &github.NewPullRequest{
		Title:               &title,
		Head:                &headBranchName,
		Base:                &baseBranchName,
		Body:                &body,
		MaintainerCanModify: github.Ptr(true),
		Draft:               &draft,
	}

	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		pr, _, err := g.PullRequests.Create(ctx, owner, repo, newPullRequest)
		if !shouldRetry(err) {
			return pr, err
		}
	}
}

func (g *githubClient) RequestPullRequestReview(
	ctx context.Context, owner, repo string, prNumber int, reviewers, teamReviewers []string,
) (*github.PullRequest, error) {
	reviewersRequest := github.ReviewersRequest{
		Reviewers:     reviewers,
		TeamReviewers: teamReviewers,
	}

	pr, _, err := g.PullRequests.RequestReviewers(ctx, owner, repo, prNumber, reviewersRequest)
	if err != nil {
		return pr, fmt.Errorf("requesting reviewers for PR %d: %w", prNumber, err)
	}

	logrus.Infof("Successfully added reviewers for PR #%d", pr.GetNumber())

	return pr, nil
}

func (g *githubClient) CreateIssue(
	ctx context.Context, owner, repo string, req *github.IssueRequest,
) (*github.Issue, error) {
	// Create the issue on github
	issue, _, err := g.Issues.Create(ctx, owner, repo, req)
	if err != nil {
		return issue, fmt.Errorf("creating new issue: %w", err)
	}

	logrus.Infof("Successfully created issue #%d: %s", issue.GetNumber(), issue.GetTitle())

	return issue, nil
}

func (g *githubClient) GetRepository(
	ctx context.Context, owner, repo string,
) (*github.Repository, *github.Response, error) {
	pr, resp, err := g.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return pr, resp, fmt.Errorf("getting repository: %w", err)
	}

	return pr, resp, nil
}

func (g *githubClient) UpdateReleasePage(
	ctx context.Context, owner, repo string, releaseID int64,
	releaseData *github.RepositoryRelease,
) (release *github.RepositoryRelease, err error) {
	// If release is 0, we create a new Release
	if releaseID == 0 {
		release, _, err = g.Repositories.CreateRelease(ctx, owner, repo, releaseData)
	} else {
		release, _, err = g.Repositories.EditRelease(ctx, owner, repo, releaseID, releaseData)
	}

	if err != nil {
		return nil, fmt.Errorf("updating release pagin in github: %w", err)
	}

	return release, nil
}

func (g *githubClient) UploadReleaseAsset(
	ctx context.Context, owner, repo string, releaseID int64, opts *github.UploadOptions, file *os.File,
) (release *github.ReleaseAsset, err error) {
	logrus.Infof("Uploading %s to release %d", opts.Name, releaseID)

	asset, _, err := g.Repositories.UploadReleaseAsset(
		ctx, owner, repo, releaseID, opts, file,
	)
	if err != nil {
		return nil, fmt.Errorf("while uploading asset file: %w", err)
	}

	return asset, nil
}

func (g *githubClient) DeleteReleaseAsset(
	ctx context.Context, owner string, repo string, assetID int64,
) error {
	_, err := g.Repositories.DeleteReleaseAsset(ctx, owner, repo, assetID)
	if err != nil {
		return fmt.Errorf("deleting asset %d: %w", assetID, err)
	}

	return nil
}

// ListReleaseAssets queries the GitHub API to get a list of asset files
// that have been uploaded to a releases.
func (g *githubClient) ListReleaseAssets(
	ctx context.Context, owner, repo string, releaseID int64, options *github.ListOptions,
) ([]*github.ReleaseAsset, error) {
	assets := []*github.ReleaseAsset{}

	for {
		moreAssets, r, err := g.Repositories.ListReleaseAssets(ctx, owner, repo, releaseID, options)
		if err != nil {
			return nil, fmt.Errorf("getting release assets from GitHub: %w", err)
		}

		assets = append(assets, moreAssets...)

		if r.NextPage == 0 {
			break
		}

		options.Page = r.NextPage
	}

	return assets, nil
}

func (g *githubClient) CreateComment(
	ctx context.Context, owner, repo string, number int, message string,
) (*github.IssueComment, *github.Response, error) {
	comment := &github.IssueComment{
		Body: &message,
	}

	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		issueComment, resp, err := g.Issues.CreateComment(ctx, owner, repo, number, comment)
		if !shouldRetry(err) {
			return issueComment, resp, err
		}
	}
}

func (g *githubClient) ListIssues(
	ctx context.Context, owner, repo string, opts *github.IssueListByRepoOptions,
) ([]*github.Issue, *github.Response, error) {
	issues, response, err := g.Issues.ListByRepo(ctx, owner, repo, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching issues from repo: %w", err)
	}

	return issues, response, nil
}

func (g *githubClient) ListComments(
	ctx context.Context,
	owner, repo string,
	number int,
	opts *github.IssueListCommentsOptions,
) ([]*github.IssueComment, *github.Response, error) {
	comments, response, err := g.Issues.ListComments(ctx, owner, repo, number, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching comments from issue: %w", err)
	}

	return comments, response, nil
}

func (g *githubClient) CheckRateLimit(
	ctx context.Context,
) (*github.RateLimits, *github.Response, error) {
	rt, response, err := g.RateLimit.Get(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching rate limit: %w", err)
	}

	return rt, response, nil
}

// SetClient can be used to manually set the internal GitHub client.
func (g *GitHub) SetClient(client Client) {
	g.client = client
}

// Client can be used to retrieve the Client type.
func (g *GitHub) Client() Client {
	return g.client
}

// SetOptions gets an options set for the GitHub object.
func (g *GitHub) SetOptions(opts *Options) {
	g.options = opts
}

// Options return a pointer to the options struct.
func (g *GitHub) Options() *Options {
	return g.options
}

// TagsPerBranch is an abstraction over a simple branch to latest tag association.
type TagsPerBranch map[string]string

// LatestGitHubTagsPerBranch returns the latest GitHub available tag for each
// branch. The logic how releases are associates with branches is motivated by
// the changelog generation and bound to the default Kubernetes release
// strategy, which is also the reason why we do not provide a repo and org
// parameter here.
//
// Releases are associated in the following way:
// - x.y.0-alpha.z releases are only associated with the main branch
// - x.y.0-beta.z releases are only associated with their release-x.y branch
// - x.y.0 final releases are associated with the main branch and the release-x.y branch.
func (g *GitHub) LatestGitHubTagsPerBranch() (TagsPerBranch, error) {
	// List tags for all pages
	allTags := []*github.RepositoryTag{}
	opts := &github.ListOptions{PerPage: g.options.GetItemsPerPage()}

	for {
		tags, resp, err := g.client.ListTags(
			context.Background(), git.DefaultGithubOrg, git.DefaultGithubRepo,
			opts,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve GitHub tags: %w", err)
		}

		allTags = append(allTags, tags...)

		if resp.NextPage == 0 {
			break
		}

		opts.Page = resp.NextPage
	}

	releases := make(TagsPerBranch)

	for _, t := range allTags {
		tag := t.GetName()

		// alpha and beta releases are only available on the main branch
		if strings.Contains(tag, "beta") || strings.Contains(tag, "alpha") {
			releases.addIfNotExisting(git.DefaultBranch, tag)

			continue
		}

		// We skip non-semver tags because k/k contains tags like `v0.5` which
		// are not valid
		semverTag, err := util.TagStringToSemver(tag)
		if err != nil {
			logrus.Debugf("Skipping tag %s because it is not valid semver", tag)

			continue
		}

		// Latest vx.x.0 release are on both main and release branch
		if len(semverTag.Pre) == 0 {
			releases.addIfNotExisting(git.DefaultBranch, tag)
		}

		branch := fmt.Sprintf("release-%d.%d", semverTag.Major, semverTag.Minor)
		releases.addIfNotExisting(branch, tag)
	}

	return releases, nil
}

// addIfNotExisting adds a new `tag` for the `branch` if not already existing
// in the map `TagsForBranch`.
func (t TagsPerBranch) addIfNotExisting(branch, tag string) {
	if _, ok := t[branch]; !ok {
		t[branch] = tag
	}
}

// Releases returns a list of GitHub releases for the provided `owner` and
// `repo`. If `includePrereleases` is `true`, then the resulting slice will
// also contain pre/drafted releases.
// TODO: Create a more descriptive method name and update references.
func (g *GitHub) Releases(owner, repo string, includePrereleases bool) ([]*github.RepositoryRelease, error) {
	allReleases, _, err := g.client.ListReleases(
		context.Background(), owner, repo, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve GitHub releases: %w", err)
	}

	releases := []*github.RepositoryRelease{}

	for _, release := range allReleases {
		if release.GetPrerelease() {
			if includePrereleases {
				releases = append(releases, release)
			}
		} else {
			releases = append(releases, release)
		}
	}

	return releases, nil
}

// GetReleaseTags returns a list of GitHub release tags for the provided
// `owner` and `repo`. If `includePrereleases` is `true`, then the resulting
// slice will also contain pre/drafted releases.
func (g *GitHub) GetReleaseTags(owner, repo string, includePrereleases bool) ([]string, error) {
	releases, err := g.Releases(owner, repo, includePrereleases)
	if err != nil {
		return nil, fmt.Errorf("getting releases: %w", err)
	}

	releaseTags := []string{}
	for _, release := range releases {
		releaseTags = append(releaseTags, *release.TagName)
	}

	return releaseTags, nil
}

// DownloadReleaseAssets downloads a set of GitHub release assets to an
// `outputDir`. Assets to download are derived from the `releaseTags`.
func (g *GitHub) DownloadReleaseAssets(owner, repo string, releaseTags []string, outputDir string) (finalErr error) {
	var releases []*github.RepositoryRelease

	if len(releaseTags) > 0 {
		for _, tag := range releaseTags {
			release, _, err := g.client.GetReleaseByTag(context.Background(), owner, repo, tag)
			if err != nil {
				return fmt.Errorf("getting release from tag %s: %w", tag, err)
			}

			releases = append(releases, release)
		}
	} else {
		return errors.New("no release tags were populated")
	}

	errChan := make(chan error, len(releases))

	for i := range releases {
		release := releases[i]

		go func(f func() error) { errChan <- f() }(func() error {
			releaseTag := release.GetTagName()
			logrus.WithField("release", releaseTag).Infof("Download assets for %s/%s@%s", owner, repo, releaseTag)

			assets := release.Assets
			if len(assets) == 0 {
				logrus.Infof("Skipping download for %s/%s@%s as no release assets were found", owner, repo, releaseTag)

				return nil
			}

			releaseDir := filepath.Join(outputDir, owner, repo, releaseTag)
			if err := os.MkdirAll(releaseDir, os.FileMode(0o775)); err != nil {
				return fmt.Errorf("creating output directory for release assets: %w", err)
			}

			logrus.WithField("release", releaseTag).Infof("Writing assets to %s", releaseDir)

			if err := g.downloadAssetsParallel(assets, owner, repo, releaseDir); err != nil {
				return fmt.Errorf("downloading assets for %s", releaseTag)
			}

			return nil
		})
	}

	for range cap(errChan) {
		if err := <-errChan; err != nil {
			if finalErr == nil {
				finalErr = err

				continue
			}

			finalErr = fmt.Errorf("%w: %w", finalErr, err)
		}
	}

	return finalErr
}

func (g *GitHub) downloadAssetsParallel(assets []*github.ReleaseAsset, owner, repo, releaseDir string) (finalErr error) {
	errChan := make(chan error, len(assets))

	for i := range assets {
		asset := assets[i]

		go func(f func() error) { errChan <- f() }(func() error {
			if asset.GetID() == 0 {
				return errors.New("asset ID should never be zero")
			}

			logrus.Infof("GitHub asset ID: %v, download URL: %s", *asset.ID, *asset.BrowserDownloadURL)

			assetBody, _, err := g.client.DownloadReleaseAsset(context.Background(), owner, repo, asset.GetID())
			if err != nil {
				return fmt.Errorf("downloading release assets: %w", err)
			}

			absFile := filepath.Join(releaseDir, asset.GetName())

			defer assetBody.Close()

			assetFile, err := os.Create(absFile)
			if err != nil {
				return fmt.Errorf("creating release asset file: %w", err)
			}

			defer assetFile.Close()

			if _, err := io.Copy(assetFile, assetBody); err != nil {
				return fmt.Errorf("copying release asset to file: %w", err)
			}

			return nil
		})
	}

	for range cap(errChan) {
		if err := <-errChan; err != nil {
			if finalErr == nil {
				finalErr = err

				continue
			}

			finalErr = fmt.Errorf("%w: %w", finalErr, err)
		}
	}

	return finalErr
}

// UploadReleaseAsset uploads a file onto the release assets.
func (g *GitHub) UploadReleaseAsset(
	owner, repo string, releaseID int64, fileName string,
) (*github.ReleaseAsset, error) {
	fileLabel := ""
	// We can get a label for the asset by appeding it to the path with a colon
	if strings.Contains(fileName, ":") {
		p := strings.SplitN(fileName, ":", 2)
		if len(p) == 2 {
			fileName = p[0]
			fileLabel = p[1]
		}
	}

	// Check the file exists
	if !util.Exists(fileName) {
		return nil, errors.New("unable to upload asset, file not found")
	}

	f, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("opening the asset file for reading: %w", err)
	}

	// Only the first 512 bytes are used to sniff the content type.
	buffer := make([]byte, 512)

	_, err = f.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("reading file to determine mimetype: %w", err)
	}
	// Reset the pointer to reuse the filehandle
	_, err = f.Seek(0, 0)
	if err != nil {
		return nil, fmt.Errorf("rewinding the asset filepointer: %w", err)
	}

	contentType := http.DetectContentType(buffer)
	logrus.Infof("Asset filetype will be %s", contentType)

	uopts := &github.UploadOptions{
		Name:      filepath.Base(fileName),
		Label:     fileLabel,
		MediaType: contentType,
	}

	asset, err := g.Client().UploadReleaseAsset(
		context.Background(), owner, repo, releaseID, uopts, f,
	)
	if err != nil {
		return nil, fmt.Errorf("uploading asset file to release: %w", err)
	}

	return asset, nil
}

// ToRequest builds an issue request from the set of options.
func (nio *NewIssueOptions) toRequest() *github.IssueRequest {
	request := &github.IssueRequest{}

	if nio.State == "open" || nio.State == "closed" || nio.State == "all" {
		request.State = &nio.State
	}

	if len(nio.Labels) > 0 {
		request.Labels = &nio.Labels
	}

	if len(nio.Assignees) == 1 {
		request.Assignee = &nio.Assignees[0]
	} else if len(nio.Assignees) > 1 {
		request.Assignees = &nio.Assignees
	}

	return request
}

// CreateIssue files a new issue in the specified respoitory.
func (g *GitHub) CreateIssue(
	owner, repo, title, body string, opts *NewIssueOptions,
) (*github.Issue, error) {
	// Create the issue request
	issueRequest := opts.toRequest()
	issueRequest.Title = &title
	issueRequest.Body = &body

	// Create the issue using the client
	return g.Client().CreateIssue(context.Background(), owner, repo, issueRequest)
}

// CreatePullRequest Creates a new pull request in owner/repo:baseBranch to merge changes from headBranchName
// which is a string containing a branch in the same repository or a user:branch pair.
func (g *GitHub) CreatePullRequest(
	owner, repo, baseBranchName, headBranchName, title, body string, draft bool,
) (*github.PullRequest, error) {
	// Use the client to create a new PR
	pr, err := g.Client().CreatePullRequest(context.Background(), owner, repo, baseBranchName, headBranchName, title, body, draft)
	if err != nil {
		return pr, err
	}

	logrus.Infof("Successfully created PR #%d", pr.GetNumber())

	return pr, nil
}

func (g *GitHub) RequestPullRequestReview(
	owner, repo string, prNumber int, reviewers, teamReviewers []string,
) (*github.PullRequest, error) {
	// Use the client to create a new PR
	pr, err := g.Client().RequestPullRequestReview(context.Background(), owner, repo, prNumber, reviewers, teamReviewers)
	if err != nil {
		return pr, err
	}

	return pr, nil
}

// GetMilestone returns a milestone object from its string name.
func (g *GitHub) GetMilestone(owner, repo, title string) (
	ms *github.Milestone, exists bool, err error,
) {
	if title == "" {
		return nil, false, errors.New("unable to search milestone. Title is empty")
	}

	opts := &github.MilestoneListOptions{
		State:       "all",
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		mstones, resp, err := g.Client().ListMilestones(
			context.Background(), owner, repo, opts)
		if err != nil {
			return nil, exists, fmt.Errorf("listing repository milestones: %w", err)
		}

		for _, ms = range mstones {
			if ms.GetTitle() == title {
				logrus.Debugf("Milestone %s is milestone ID#%d", ms.GetTitle(), ms.GetID())

				return ms, true, nil
			}
		}

		if resp.NextPage == 0 {
			break
		}

		opts.Page = resp.NextPage
	}

	return nil, false, nil
}

// GetRepository gets a repository using the current client.
func (g *GitHub) GetRepository(
	owner, repo string,
) (*github.Repository, error) {
	repository, _, err := g.Client().GetRepository(context.Background(), owner, repo)
	if err != nil {
		return repository, err
	}

	return repository, nil
}

// ListBranches gets a repository using the current client.
func (g *GitHub) ListBranches(
	owner, repo string,
) ([]*github.Branch, error) {
	options := &github.BranchListOptions{
		ListOptions: github.ListOptions{PerPage: g.Options().GetItemsPerPage()},
	}
	branches := []*github.Branch{}

	for {
		moreBranches, r, err := g.Client().ListBranches(context.Background(), owner, repo, options)
		if err != nil {
			return branches, fmt.Errorf("getting branches from client: %w", err)
		}

		branches = append(branches, moreBranches...)

		if r.NextPage == 0 {
			break
		}

		options.Page = r.NextPage
	}

	return branches, nil
}

// RepoIsForkOf Function that checks if a repository is a fork of another.
func (g *GitHub) RepoIsForkOf(
	forkOwner, forkRepo, parentOwner, parentRepo string,
) (bool, error) {
	repository, _, err := g.Client().GetRepository(context.Background(), forkOwner, forkRepo)
	if err != nil {
		return false, fmt.Errorf("checking if repository is a fork: %w", err)
	}

	// First, repo has to be an actual fork
	if !repository.GetFork() {
		logrus.Infof("Repository %s/%s is not a fork", forkOwner, forkRepo)

		return false, nil
	}

	// Check if the parent repo matches the owner/repo string
	if repository.GetParent().GetFullName() == fmt.Sprintf("%s/%s", parentOwner, parentRepo) {
		logrus.Debugf("%s/%s is a fork of %s/%s", forkOwner, forkRepo, parentOwner, parentRepo)

		return true, nil
	}

	logrus.Infof("%s/%s is not a fork of %s/%s", forkOwner, forkRepo, parentOwner, parentRepo)

	return false, nil
}

// BranchExists checks if a branch exists in a given repo.
func (g *GitHub) BranchExists(
	owner, repo, branchname string,
) (isBranch bool, err error) {
	branches, err := g.ListBranches(owner, repo)
	if err != nil {
		return false, fmt.Errorf("while listing repository branches: %w", err)
	}

	for _, branch := range branches {
		if branch.GetName() == branchname {
			logrus.Debugf("Branch %s already exists in %s/%s", branchname, owner, repo)

			return true, nil
		}
	}

	logrus.Debugf("Repository %s/%s does not have a branch named %s", owner, repo, branchname)

	return false, nil
}

// UpdateReleasePage updates a release page in GitHub.
func (g *GitHub) UpdateReleasePage(
	owner, repo string,
	releaseID int64,
	tag, commitish, name, body string,
	isDraft, isPrerelease bool,
) (release *github.RepositoryRelease, err error) {
	return g.UpdateReleasePageWithOptions(owner, repo, releaseID, tag, commitish, &UpdateReleasePageOptions{
		Name:       &name,
		Body:       &body,
		Draft:      &isDraft,
		Prerelease: &isPrerelease,
	})
}

// toRepositoryRelease builds a repository release from the set of options.
func (u *UpdateReleasePageOptions) toRepositoryRelease() *github.RepositoryRelease {
	request := &github.RepositoryRelease{}
	request.Name = u.Name
	request.Body = u.Body
	request.Draft = u.Draft
	request.Prerelease = u.Prerelease

	if u.Latest != nil {
		if *u.Latest {
			request.MakeLatest = ptr.To("true")
		} else {
			request.MakeLatest = ptr.To("false")
		}
	}

	return request
}

// UpdateReleasePageWithOptions updates release pages (same as UpdateReleasePage),
// but does so by taking a UpdateReleasePageOptions parameter. It will _not_ set
// a release as latest unless the corresponding option is set.
func (g *GitHub) UpdateReleasePageWithOptions(owner, repo string,
	releaseID int64,
	tag, commitish string,
	opts *UpdateReleasePageOptions,
) (release *github.RepositoryRelease, err error) {
	logrus.Infof("Updating release page for %s", tag)

	if opts == nil {
		opts = &UpdateReleasePageOptions{}
	}

	releaseData := opts.toRepositoryRelease()
	releaseData.TagName = &tag
	releaseData.TargetCommitish = &commitish

	// Call the client.
	release, err = g.Client().UpdateReleasePage(
		context.Background(), owner, repo, releaseID, releaseData,
	)
	if err != nil {
		return nil, fmt.Errorf("updating the release page: %w", err)
	}

	return release, nil
}

// DeleteReleaseAsset deletes an asset from a release.
func (g *GitHub) DeleteReleaseAsset(owner, repo string, assetID int64) error {
	if err := g.Client().DeleteReleaseAsset(
		context.Background(), owner, repo, assetID,
	); err != nil {
		return fmt.Errorf("deleting asset from release: %w", err)
	}

	return nil
}

// ListReleaseAssets gets the assets uploaded to a GitHub release.
func (g *GitHub) ListReleaseAssets(
	owner, repo string, releaseID int64,
) ([]*github.ReleaseAsset, error) {
	// Get the assets from the client
	assets, err := g.Client().ListReleaseAssets(
		context.Background(), owner, repo, releaseID,
		&github.ListOptions{PerPage: g.Options().GetItemsPerPage()},
	)
	if err != nil {
		return nil, fmt.Errorf("getting release assets: %w", err)
	}

	return assets, nil
}

// TagExists returns true is a specified tag exists in the repo.
func (g *GitHub) TagExists(owner, repo, tag string) (exists bool, err error) {
	options := &github.ListOptions{PerPage: g.Options().GetItemsPerPage()}

	for {
		tags, r, err := g.Client().ListTags(
			context.Background(), owner, repo, options,
		)
		if err != nil {
			return exists, fmt.Errorf("listing repository tags: %w", err)
		}

		// List all tags returned and check if the one we're looking for exists
		for _, testTag := range tags {
			if testTag.GetName() == tag {
				return true, nil
			}
		}

		if r.NextPage == 0 {
			break
		}

		options.Page = r.NextPage
	}

	return false, nil
}

// ListTags gets the tags from a GitHub repository.
func (g *GitHub) ListTags(owner, repo string) ([]*github.RepositoryTag, error) {
	options := &github.ListOptions{PerPage: g.Options().GetItemsPerPage()}
	tags := []*github.RepositoryTag{}

	for {
		repoTags, r, err := g.Client().ListTags(
			context.Background(), owner, repo, options,
		)
		if err != nil {
			return tags, fmt.Errorf("listing repository tags: %w", err)
		}

		tags = append(tags, repoTags...)

		if r.NextPage == 0 {
			break
		}

		options.Page = r.NextPage
	}

	return tags, nil
}

// RateLimit returns the rate limits for the current client.
func (g *GitHub) CheckRateLimit(ctx context.Context) (*github.RateLimits, *github.Response, error) {
	return g.Client().CheckRateLimit(ctx)
}

func (g *githubClient) UpdateIssue(
	ctx context.Context, owner, repo string, number int, issueRequest *github.IssueRequest,
) (*github.Issue, *github.Response, error) {
	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		issue, resp, err := g.Issues.Edit(ctx, owner, repo, number, issueRequest)
		if !shouldRetry(err) {
			return issue, resp, err
		}
	}
}

func (g *githubClient) AddLabels(
	ctx context.Context, owner, repo string, number int, labels []string,
) ([]*github.Label, *github.Response, error) {
	for shouldRetry := ghinternal.DefaultGithubErrChecker(); ; {
		appliedLabels, resp, err := g.Issues.AddLabelsToIssue(ctx, owner, repo, number, labels)
		if !shouldRetry(err) {
			return appliedLabels, resp, err
		}
	}
}

// IssueState is the enum for all available issue states.
type IssueState string

const (
	// IssueStateAll can be used to list all issues.
	IssueStateAll IssueState = "all"

	// IssueStateOpen can be used to list only open issues.
	IssueStateOpen IssueState = "open"

	// IssueStateClosed can be used to list only closed issues.
	IssueStateClosed IssueState = "closed"
)

// ListIssues gets the issues from a GitHub repository.
// State filters issues based on their state. Possible values are: open,
// closed, all. Default is "open".
func (g *GitHub) ListIssues(owner, repo string, state IssueState) ([]*github.Issue, error) {
	opts := &github.IssueListByRepoOptions{
		State:       string(state),
		ListOptions: github.ListOptions{PerPage: g.Options().GetItemsPerPage()},
	}
	issues := []*github.Issue{}

	for {
		more, r, err := g.Client().ListIssues(context.Background(), owner, repo, opts)
		if err != nil {
			return issues, fmt.Errorf("getting issues from client: %w", err)
		}

		issues = append(issues, more...)

		if r.NextPage == 0 {
			break
		}

		opts.ListOptions.Page = r.NextPage
	}

	return issues, nil
}

// Sort specifies how to sort comments. Possible values are: created, updated.
type Sort string

// SortDirection in which to sort comments. Possible values are: asc, desc.
type SortDirection string

const (
	SortCreated Sort = "created"
	SortUpdated Sort = "updated"

	SortDirectionAscending  SortDirection = "asc"
	SortDirectionDescending SortDirection = "desc"
)

// ListComments lists all comments on the specified issue. Specifying an issue
// number of 0 will return all comments on all issues for the repository.
//
// GitHub API docs: https://docs.github.com/en/rest/issues/comments#list-issue-comments
// GitHub API docs: https://docs.github.com/en/rest/issues/comments#list-issue-comments-for-a-repository
func (g *GitHub) ListComments(
	owner, repo string,
	issueNumber int,
	sort Sort,
	direction SortDirection,
	since *time.Time,
) ([]*github.IssueComment, error) {
	options := &github.IssueListCommentsOptions{
		Sort:        github.Ptr(string(sort)),
		Direction:   github.Ptr(string(direction)),
		ListOptions: github.ListOptions{PerPage: g.Options().GetItemsPerPage()},
	}

	if since != nil {
		options.Since = since
	}

	comments := []*github.IssueComment{}

	for {
		more, r, err := g.Client().ListComments(context.Background(), owner, repo, issueNumber, options)
		if err != nil {
			return comments, fmt.Errorf("getting comments from client: %w", err)
		}

		comments = append(comments, more...)

		if r.NextPage == 0 {
			break
		}

		options.Page = r.NextPage
	}

	return comments, nil
}
