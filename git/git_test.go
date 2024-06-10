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

package git_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/release-sdk/git"
	"sigs.k8s.io/release-sdk/git/gitfakes"
	"sigs.k8s.io/release-utils/command"
)

var testAuthor = &object.Signature{
	Name:  "John Doe",
	Email: "john@doe.org",
	When:  time.Now(),
}

const (
	errDesc = "opening test repo in "
	origin  = "origin"
)

func newSUT() (*git.Repo, *gitfakes.FakeWorktree) {
	repoMock := &gitfakes.FakeRepository{}
	worktreeMock := &gitfakes.FakeWorktree{}

	repo := &git.Repo{}
	repo.SetWorktree(worktreeMock)
	repo.SetInnerRepo(repoMock)

	return repo, worktreeMock
}

func TestCommit(t *testing.T) {
	repo, worktreeMock := newSUT()
	require.Nil(t, repo.Commit("msg"))
	require.Equal(t, worktreeMock.CommitCallCount(), 1)
}

func TestGetDefaultKubernetesRepoURLSuccess(t *testing.T) {
	testcases := []struct {
		name     string
		org      string
		useSSH   bool
		expected string
	}{
		{
			name:     "default HTTPS",
			expected: "https://github.com/kubernetes/kubernetes",
		},
	}

	for _, tc := range testcases {
		t.Logf("Test case: %s", tc.name)

		actual := git.GetDefaultKubernetesRepoURL()
		require.Equal(t, tc.expected, actual)
	}
}

// createTestRepository creates a test repo, cd into it and returns the path
func createTestRepository() (repoPath string, err error) {
	repoPath, err = os.MkdirTemp("", "sigrelease-test-repo-*")
	if err != nil {
		return "", fmt.Errorf("creating a directory for test repository: %w", err)
	}
	if err := os.Chdir(repoPath); err != nil {
		return "", fmt.Errorf("cd'ing into test repository: %w", err)
	}
	out, err := exec.Command("git", "init").Output()
	if err != nil {
		return "", fmt.Errorf("initializing test repository: %s: %w", out, err)
	}
	return repoPath, nil
}

func TestGetUserName(t *testing.T) {
	require.Empty(t, os.Getenv("GIT_COMMITTER_NAME"))

	const fakeUserName = "SIG Release Test User"
	currentDir, err := os.Getwd()
	require.Nil(t, err, "error reading the current directory")
	defer os.Chdir(currentDir) //nolint: errcheck

	// Create an empty repo and configure the users name to test
	repoPath, err := createTestRepository()
	require.Nil(t, err, "getting a test repo")

	// Call git to configure the user's name:
	_, err = exec.Command("git", "config", "user.name", fakeUserName).Output()
	require.Nil(t, err, "configuring fake user email in "+repoPath)

	testRepo, err := git.OpenRepo(repoPath)
	require.Nil(t, err, errDesc+repoPath)
	defer testRepo.Cleanup() //nolint: errcheck

	actual, err := git.GetUserName()
	require.Nil(t, err)
	require.Equal(t, fakeUserName, actual)
	require.NotEqual(t, fakeUserName, "")

	envVarName := fakeUserName + " env var"
	require.Nil(t, os.Setenv("GIT_COMMITTER_NAME", envVarName))
	actual, err = git.GetUserName()
	require.Nil(t, err)
	require.Equal(t, envVarName, actual)
	require.NotEqual(t, fakeUserName, "")
	require.Nil(t, os.Unsetenv("GIT_COMMITTER_NAME"))
}

func TestGetUserEmail(t *testing.T) {
	require.Empty(t, os.Getenv("GIT_COMMITTER_EMAIL"))

	const fakeUserEmail = "kubernetes-test@example.com"
	currentDir, err := os.Getwd()
	require.Nil(t, err, "error reading the current directory")
	defer os.Chdir(currentDir) //nolint: errcheck

	// Create an empty repo and configure the users name to test
	repoPath, err := createTestRepository()
	require.Nil(t, err, "getting a test repo")

	// Call git to configure the user's name:
	_, err = exec.Command("git", "config", "user.email", fakeUserEmail).Output()
	require.Nil(t, err, "configuring fake user email in "+repoPath)

	testRepo, err := git.OpenRepo(repoPath)
	require.Nil(t, err, errDesc+repoPath)
	defer testRepo.Cleanup() //nolint: errcheck

	// Do the actual call
	actual, err := git.GetUserEmail()
	require.Nil(t, err)
	require.Equal(t, fakeUserEmail, actual)
	require.NotEqual(t, fakeUserEmail, "")

	envVarEmail := "kubernetes-honk@example.com"
	require.Nil(t, os.Setenv("GIT_COMMITTER_EMAIL", envVarEmail))
	actual, err = git.GetUserEmail()
	require.Nil(t, err)
	require.Equal(t, envVarEmail, actual)
	require.NotEqual(t, envVarEmail, "")
	require.Nil(t, os.Unsetenv("GIT_COMMITTER_EMAIL"))
}

func TestGetKubernetesRepoURLSuccess(t *testing.T) {
	testcases := []struct {
		name     string
		org      string
		useSSH   bool
		expected string
	}{
		{
			name:     "default HTTPS",
			expected: "https://github.com/kubernetes/kubernetes",
		},
		{
			name:     "ssh with custom org",
			org:      "fake-org",
			useSSH:   true,
			expected: "git@github.com:fake-org/kubernetes",
		},
	}

	for _, tc := range testcases {
		t.Logf("Test case: %s", tc.name)

		actual := git.GetKubernetesRepoURL(tc.org, tc.useSSH)
		require.Equal(t, tc.expected, actual)
	}
}

func TestGetRepoURLSuccess(t *testing.T) {
	testcases := []struct {
		name     string
		org      string
		repo     string
		useSSH   bool
		expected string
	}{
		{
			name:     "default Kubernetes HTTPS",
			org:      "kubernetes",
			repo:     "kubernetes",
			expected: "https://github.com/kubernetes/kubernetes",
		},
		{
			name:     "ssh with custom org",
			org:      "fake-org",
			repo:     "repofoo",
			useSSH:   true,
			expected: "git@github.com:fake-org/repofoo",
		},
	}

	for _, tc := range testcases {
		t.Logf("Test case: %s", tc.name)

		actual := git.GetRepoURL(tc.org, tc.repo, tc.useSSH)
		require.Equal(t, tc.expected, actual)
	}
}

func TestRemotify(t *testing.T) {
	testcases := []struct{ provided, expected string }{
		{provided: git.DefaultBranch, expected: git.DefaultRemote + "/" + git.DefaultBranch},
		{provided: origin + "/ref", expected: origin + "/ref"},
		{provided: "base/another_ref", expected: "base/another_ref"},
	}

	for _, tc := range testcases {
		require.Equal(t, git.Remotify(tc.provided), tc.expected)
	}
}

func TestIsDirtyMockSuccess(t *testing.T) {
	repo, _ := newSUT()

	dirty, err := repo.IsDirty()

	require.Nil(t, err)
	require.False(t, dirty)
}

func TestIsDirtyMockSuccessDirty(t *testing.T) {
	repo, worktreeMock := newSUT()
	worktreeMock.StatusReturns(gogit.Status{
		"file": &gogit.FileStatus{
			Worktree: gogit.Modified,
		},
	}, nil)

	dirty, err := repo.IsDirty()

	require.Nil(t, err)
	require.True(t, dirty)
}

func TestIsDirtyMockFailureWorktreeStatus(t *testing.T) {
	repo, worktreeMock := newSUT()
	worktreeMock.StatusReturns(gogit.Status{}, errors.New(""))

	dirty, err := repo.IsDirty()

	require.NotNil(t, err)
	require.False(t, dirty)
}

func TestParseRepoSlug(t *testing.T) {
	slugTests := []struct {
		caseName, repoSlug, orgName, repoName string
		isValid                               bool
	}{
		{
			caseName: "valid slug", repoSlug: "kubernetes/release",
			orgName: "kubernetes", repoName: "release", isValid: true,
		},

		{
			caseName: "slug with hyphens", repoSlug: "kubernetes/repo_with_underscores",
			orgName: "", repoName: "", isValid: false,
		},

		{
			caseName: "slug with dashes", repoSlug: "kubernetes-sigs/release-notes",
			orgName: "kubernetes-sigs", repoName: "release-notes", isValid: true,
		},

		{
			caseName: "slug with uppercase", repoSlug: "GoogleCloudPlatform/compute-image-tools",
			orgName: "GoogleCloudPlatform", repoName: "compute-image-tools", isValid: true,
		},

		{
			caseName: "slug with invalid chars", repoSlug: "kubern#etes/not.valid",
			orgName: "", repoName: "", isValid: false,
		},

		{
			caseName: "slug with extra slash", repoSlug: "kubernetes/not/valid",
			orgName: "", repoName: "", isValid: false,
		},

		{
			caseName: "slug with only org", repoSlug: "kubernetes",
			orgName: "kubernetes", repoName: "", isValid: true,
		},
	}

	for _, testCase := range slugTests {
		org, repo, err := git.ParseRepoSlug(testCase.repoSlug)
		if testCase.isValid {
			require.Nil(t, err, testCase.caseName)
		} else {
			require.NotNil(t, err, testCase.caseName)
		}
		require.Equal(t, testCase.orgName, org, testCase.caseName)
		require.Equal(t, testCase.repoName, repo, testCase.caseName)
	}
}

func TestRetryErrors(t *testing.T) {
	retryErrorStrings := []string{
		"dial tcp: lookup github.com on [::1]:53",
		"read udp [::1]:48087->[::1]:53",
		"read: connection refused",
	}

	nonRetryErrorStrings := []string{
		"could not list references on the remote repository",
		"error checking remote branch",
		"src refspec release-chorizo does not match",
	}

	for _, message := range retryErrorStrings {
		err := git.NewNetworkError(errors.New(message))
		require.True(t, err.CanRetry(), fmt.Sprintf("Checking retriable error '%s'", message))
	}

	for _, message := range nonRetryErrorStrings {
		err := git.NewNetworkError(errors.New(message))
		require.False(t, err.CanRetry(), fmt.Sprintf("Checking non-retriable error '%s'", message))
	}
}

func TestNetworkError(t *testing.T) {
	// Return a NetWorkError in a fun that returns a standard error
	err := func() error {
		return git.NewNetworkError(errors.New("This is a test error"))
	}()
	require.NotNil(t, err, "checking if NewNetWork error returns nil")
	require.NotEmpty(t, err.Error(), "checking if NetworkError returns a message")
	require.False(t, err.(git.NetworkError).CanRetry(), "checking if network error can be properly asserted")
}

func TestHasBranch(t *testing.T) {
	testBranchName := "git-package-test-branch"
	repoPath, err := createTestRepository()
	require.Nil(t, err, "getting a test repo")

	// Create a file and a test commit
	testfile := filepath.Join(repoPath, "README.md")
	err = os.WriteFile(testfile, []byte("# WHY SIG-RELEASE ROCKS\n\n"), os.FileMode(0o644))
	require.Nil(t, err, "writing test file")

	err = command.NewWithWorkDir(repoPath, "git", "add", testfile).RunSuccess()
	require.Nil(t, err, "adding test file in "+repoPath)

	err = command.NewWithWorkDir(repoPath, "git", "commit", "-m", "adding test file").RunSuccess()
	require.Nil(t, err, "creating first commit")

	// Call git to configure the user's name:
	err = command.NewWithWorkDir(repoPath, "git", "branch", testBranchName).RunSuccess()
	require.Nil(t, err, "configuring test branch in "+repoPath)

	// Now, open the repo and test to see if branches are there
	testRepo, err := git.OpenRepo(repoPath)
	require.Nil(t, err, errDesc+repoPath)
	defer testRepo.Cleanup() //nolint: errcheck

	actual, err := testRepo.HasBranch(testBranchName)
	require.Nil(t, err)
	require.True(t, actual)

	actual, err = testRepo.HasBranch(git.DefaultBranch)
	require.Nil(t, err)
	require.True(t, actual)

	actual, err = testRepo.HasBranch("non-existing-branch")
	require.Nil(t, err)
	require.False(t, actual)
}

func TestStatus(t *testing.T) {
	rawRepoDir, err := os.MkdirTemp("", "k8s-test-repo")
	require.Nil(t, err)
	_, err = gogit.PlainInit(rawRepoDir, false)
	require.Nil(t, err)

	testFile := "test-status.txt"

	testRepo, err := git.OpenRepo(rawRepoDir)
	require.Nil(t, err)
	defer testRepo.Cleanup() //nolint: errcheck

	// Get the status object
	status, err := testRepo.Status()
	require.Nil(t, err)
	require.NotNil(t, status)
	require.True(t, status.IsClean())

	// Create an untracked file
	require.Nil(t, os.WriteFile(filepath.Join(testRepo.Dir(), testFile), []byte("Hello SIG Release"), 0o644))

	// Status should be modified now
	status, err = testRepo.Status()
	require.Nil(t, err)
	require.Equal(t, fmt.Sprintf("?? %s\n", testFile), status.String())

	// Add the file, should status should be A
	require.Nil(t, testRepo.Add(testFile))
	status, err = testRepo.Status()
	require.Nil(t, err)
	require.Equal(t, fmt.Sprintf("A  %s\n", testFile), status.String())

	// Commit the file, status should be blank again
	require.Nil(t, testRepo.Commit("Commit test file"))
	status, err = testRepo.Status()
	require.Nil(t, err)
	require.Empty(t, status.String())

	// Modify the file
	require.Nil(t, os.WriteFile(filepath.Join(testRepo.Dir(), testFile), []byte("Bye SIG Release"), 0o644))
	status, err = testRepo.Status()
	require.Nil(t, err)
	require.Equal(t, fmt.Sprintf(" M %s\n", testFile), status.String())
}

func TestShowLastCommit(t *testing.T) {
	rawRepoDir, err := os.MkdirTemp("", "k8s-test-repo")
	require.Nil(t, err)
	_, err = gogit.PlainInit(rawRepoDir, false)
	require.Nil(t, err)

	testFile := "test-last-commit.txt"
	timeNow := strconv.FormatInt(time.Now().UnixNano(), 10)

	testRepo, err := git.OpenRepo(rawRepoDir)
	require.Nil(t, err)
	defer testRepo.Cleanup() //nolint: errcheck

	// Create an untracked file
	require.Nil(t, os.WriteFile(filepath.Join(testRepo.Dir(), testFile), []byte("Hello SIG Release"), 0o644))
	require.Nil(t, testRepo.Add(testFile))
	require.Nil(t, testRepo.Commit("Commit test file at "+timeNow))

	// Now get the log message back and check if it contains the time
	lastLog, err := testRepo.ShowLastCommit()
	require.Nil(t, err)
	require.NotEmpty(t, lastLog)
	require.True(t, strings.Contains(lastLog, timeNow))
}

func TestFetchRemote(t *testing.T) {
	testTagName := "test-tag" + strconv.FormatInt(time.Now().UnixNano(), 10)
	// Create a new empty repo
	rawRepoDir, err := os.MkdirTemp("", "k8s-test-repo")
	require.Nil(t, err)
	gogitRepo, err := gogit.PlainInit(rawRepoDir, false)
	require.Nil(t, err)

	// Create the foirst commit
	wtree, err := gogitRepo.Worktree()
	require.Nil(t, err)
	require.Nil(t, err)
	commitSha, err := wtree.Commit("Initial Commit", &gogit.CommitOptions{
		Author:            testAuthor,
		AllowEmptyCommits: true,
	})
	require.Nil(t, err)

	// Create a git.Repo from it
	originRepo, err := git.OpenRepo(rawRepoDir)
	require.Nil(t, err)

	branchName, err := originRepo.CurrentBranch()
	require.Nil(t, err)
	defer originRepo.Cleanup() //nolint: errcheck

	// Create a new clone of the original repo
	testRepo, err := git.CloneOrOpenRepo("", rawRepoDir, false, true, nil)
	require.Nil(t, err)
	defer testRepo.Cleanup() //nolint: errcheck

	// The initial clone must not have any tags
	testTags, err := testRepo.TagsForBranch(branchName)
	require.Nil(t, err)
	require.Empty(t, testTags)

	// Create a tag on the originRepo
	_, err = gogitRepo.CreateTag(testTagName, commitSha, &gogit.CreateTagOptions{
		Message: testTagName,
		Tagger:  testAuthor,
	})
	require.Nil(t, err)

	// Now, call fetch
	newContent, err := testRepo.FetchRemote(origin)
	require.Nil(t, err, "Calling fetch to get a test tag")
	require.True(t, newContent)

	// Fetching again should provide no updates
	newContent, err = testRepo.FetchRemote(origin)
	require.Nil(t, err, "Calling fetch to get a test tag again")
	require.False(t, newContent)

	// And now we can verify the tags was successfully transferred via FetchRemote()
	testTags, err = testRepo.TagsForBranch(branchName)
	require.Nil(t, err)
	require.NotEmpty(t, testTags)
	require.ElementsMatch(t, []string{testTagName}, testTags)
}

func TestRebase(t *testing.T) {
	testFile := "test-rebase.txt"

	// Create a new empty repo
	rawRepoDir, err := os.MkdirTemp("", "k8s-test-repo")
	require.Nil(t, err)
	gogitRepo, err := gogit.PlainInit(rawRepoDir, false)
	require.Nil(t, err)

	// Create the initial commit
	wtree, err := gogitRepo.Worktree()
	require.Nil(t, err)
	_, err = wtree.Commit("Initial Commit", &gogit.CommitOptions{
		Author:            testAuthor,
		AllowEmptyCommits: true,
	})
	require.Nil(t, err)

	// Create a git.Repo from it
	originRepo, err := git.OpenRepo(rawRepoDir)
	require.Nil(t, err)

	branchName, err := originRepo.CurrentBranch()
	require.Nil(t, err)
	defer originRepo.Cleanup() //nolint: errcheck

	// Create a new clone of the original repo
	testRepo, err := git.CloneOrOpenRepo("", rawRepoDir, false, true, nil)
	require.Nil(t, err)
	defer testRepo.Cleanup() //nolint: errcheck

	// Test 1. Rebase should not fail if both repos are in sync
	require.Nil(t, testRepo.Rebase(origin+"/"+branchName), "cloning synchronizaed repos")

	// Test 2. Rebase should not fail with pulling changes in the remote
	require.Nil(t, os.WriteFile(filepath.Join(rawRepoDir, testFile), []byte("Hello SIG Release"), 0o644))
	_, err = wtree.Add(testFile)
	require.Nil(t, err)

	_, err = wtree.Commit("Test2-Commit", &gogit.CommitOptions{
		Author: testAuthor,
	})
	require.Nil(t, err)

	// Pull the changes to the test repo
	newContent, err := testRepo.FetchRemote(origin)
	require.Nil(t, err)
	require.True(t, newContent)

	// Do the Rebase
	require.Nil(t, testRepo.Rebase(origin+"/"+branchName), "rebasing changes from origin")

	// Verify we got the commit
	lastLog, err := testRepo.ShowLastCommit()
	require.Nil(t, err)
	require.True(t, strings.Contains(lastLog, "Test2-Commit"))

	// Test 3: Rebase must on an invalid branch
	require.NotNil(t, testRepo.Rebase(origin+"/invalidBranch"), "rebasing to invalid branch")

	// Test 4: Rebase must fail on merge conflicts
	require.Nil(t, os.WriteFile(filepath.Join(rawRepoDir, testFile), []byte("Hello again SIG Release"), 0o644))
	_, err = wtree.Add(testFile)
	require.Nil(t, err)

	_, err = wtree.Commit("Test4-Commit", &gogit.CommitOptions{
		Author: testAuthor,
	})
	require.Nil(t, err)

	// Commit the same file in the test repo
	require.Nil(t, os.WriteFile(filepath.Join(testRepo.Dir(), testFile), []byte("Conflict me!"), 0o644))
	require.Nil(t, testRepo.Add(filepath.Join(testRepo.Dir(), testFile)))
	require.Nil(t, testRepo.Commit("Adding file to cause conflict"))

	// Now, fetch and rebase
	newContent, err = testRepo.FetchRemote(origin)
	require.Nil(t, err)
	require.True(t, newContent)

	err = testRepo.Rebase(origin + "/" + branchName)
	require.NotNil(t, err, "testing for merge conflicts")
}

func TestLastCommitSha(t *testing.T) {
	// Create a test repository
	rawRepoDir, err := os.MkdirTemp("", "k8s-test-repo")
	require.Nil(t, err)
	defer os.RemoveAll(rawRepoDir)
	_, err = gogit.PlainInit(rawRepoDir, false)
	require.Nil(t, err)

	repo, err := git.OpenRepo(rawRepoDir)
	require.Nil(t, err)

	// Create two commits in the repository
	shas := make([]string, 2)
	for _, i := range []int{0, 1} {
		require.Nil(t, repo.CommitEmpty(fmt.Sprintf("Empty commit %d", i+1)))
		shas[i], err = repo.LastCommitSha()
		require.Nil(t, err)
		require.NotEmpty(t, shas[i])
	}
	require.Len(t, shas, 2)

	// Now, checkout the first one and check we get the right hash
	require.Nil(t, repo.Checkout("HEAD~1"))

	lastCommit, err := repo.LastCommitSha()
	require.Nil(t, err)
	require.Equal(t, shas[0], lastCommit, "Checking HEAD~1 sha matches commit #1")
	require.NotEqual(t, shas[1], lastCommit, "Checking HEAD~1 sha does not matches commit #2")
}

func TestNextCommit(t *testing.T) {
	// Create a test repository
	rawRepoDir, err := os.MkdirTemp("", "k8s-test-repo-")
	require.Nil(t, err)
	defer os.RemoveAll(rawRepoDir)
	_, err = gogit.PlainInit(rawRepoDir, false)
	require.Nil(t, err)

	repo, err := git.OpenRepo(rawRepoDir)
	require.Nil(t, err)

	// Create commits in the repository
	shas := make([]string, 3)
	for _, i := range []int{0, 1, 2} {
		require.Nil(t, repo.CommitEmpty(fmt.Sprintf("Empty commit %d", i+1)))
		shas[i], err = repo.LastCommitSha()
		require.Nil(t, err)
		require.NotEmpty(t, shas[i])
		require.Nil(t, repo.Tag(fmt.Sprintf("tag-%d", i), "New tag"))
	}
	require.Len(t, shas, 3)

	// shas[0] is the child of shas[1]
	nextCommit, err := repo.NextCommit(shas[0], git.DefaultBranch)
	require.Nil(t, err)
	require.Equal(t, shas[1], nextCommit)

	// shas[1] is the child of shas[2]
	nextCommit, err = repo.NextCommit(shas[1], git.DefaultBranch)
	require.Nil(t, err)
	require.Equal(t, shas[2], nextCommit)

	// shas[2] has no child
	nextCommit, err = repo.NextCommit(shas[2], git.DefaultBranch)
	require.Nil(t, err)
	require.Empty(t, nextCommit)

	// tag-0 is the child of shas[1]
	nextCommit, err = repo.NextCommit("tag-0", git.DefaultBranch)
	require.Nil(t, err)
	require.Equal(t, shas[1], nextCommit)

	// tag-1 is the child of shas[2]
	nextCommit, err = repo.NextCommit("tag-1", git.DefaultBranch)
	require.Nil(t, err)
	require.Equal(t, shas[2], nextCommit)

	// tag-2 has no child
	nextCommit, err = repo.NextCommit("tag-2", git.DefaultBranch)
	require.Nil(t, err)
	require.Empty(t, nextCommit)

	// branch does not exist
	nextCommit, err = repo.NextCommit(shas[0], "does-not-exist")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "unknown revision")
	require.Empty(t, nextCommit)

	// commit does not exist
	nextCommit, err = repo.NextCommit("does-not-exist", git.DefaultBranch)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "unknown revision")
	require.Empty(t, nextCommit)
}
