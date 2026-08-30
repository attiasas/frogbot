package autopr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jfrog/froggit-go/vcsclient"
	securitypkgupdaters "github.com/jfrog/jfrog-cli-security/remediation/sca/packageupdaters"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/frogbot/v3/utils"
	"github.com/jfrog/frogbot/v3/utils/outputwriter"
)

const (
	componentNameEnv   = "JF_COMPONENT_NAME"
	affectedVersionEnv = "JF_AFFECTED_VERSION"
	fixVersionEnv      = "JF_FIX_VERSION"
	commitHashEnv      = "JF_COMMIT_HASH"
)

// ErrAutoPrSkipped is returned when auto-pr cannot proceed but the situation is not fatal
// (e.g. component not found, fix branch already exists). Callers can distinguish it from real failures.
type ErrAutoPrSkipped struct {
	Reason string
}

func (e *ErrAutoPrSkipped) Error() string {
	return fmt.Sprintf("auto-pr skipped: %s", e.Reason)
}

type autoPrGitManager interface {
	GenerateFixBranchName(string, string, string) (string, error)
	BranchExistsInRemote(string) (bool, error)
	IsClean() (bool, error)
	CreateBranchAndCheckout(string, bool) error
	GenerateCommitMessage(string, string) string
	AddTrackedAndCommit(string, string) error
	Push(bool, string) error
	GeneratePullRequestTitle(string, string) string
}

type AutoPrCmd struct {
	newGitManager       func(utils.Repository) (autoPrGitManager, error)
	findDescriptorPaths func(string, string, string) ([]string, techutils.Technology, bool, error)
	runUpdater          func(string, string, string, techutils.Technology, bool, []string) error
	createPullRequest   func(utils.Repository, string, string, string, string, []string) error
}

type autoPrRun struct {
	componentName   string
	affectedVersion string
	fixVersion      string
	baseBranch      string
	fixBranchName   string
	workspaceDir    string
	descriptorPaths []string
	tech            techutils.Technology
}

func (a *AutoPrCmd) Run(repository utils.Repository, client vcsclient.VcsClient) error {
	run := autoPrRun{
		componentName:   os.Getenv(componentNameEnv),
		affectedVersion: os.Getenv(affectedVersionEnv),
		fixVersion:      os.Getenv(fixVersionEnv),
		baseBranch:      repository.Params.Git.Branches[0],
	}
	if err := validateInputs(run.componentName, run.affectedVersion, run.fixVersion); err != nil {
		return err
	}
	log.Info(fmt.Sprintf("Starting auto-pr for component '%s' (%s → %s) in %s/%s",
		run.componentName, run.affectedVersion, run.fixVersion,
		repository.Params.Git.RepoOwner, repository.Params.Git.RepoName))

	gitManager, err := a.initializeGitManager(repository)
	if err != nil {
		return err
	}
	if err = a.prepareRun(&run, gitManager); err != nil {
		return err
	}
	return a.applyFixAndCreatePullRequest(run, repository, client, gitManager)
}

func (a *AutoPrCmd) initializeGitManager(repository utils.Repository) (autoPrGitManager, error) {
	if a.newGitManager != nil {
		return a.newGitManager(repository)
	}
	gitManager, err := utils.NewGitManager().
		SetAuth(repository.Params.Git.Username, repository.Params.Git.Token).
		SetRemoteGitUrl(repository.Params.Git.RepositoryCloneUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize git manager: %w", err)
	}
	var commitMessageTemplate, branchNameTemplate, prTitleTemplate string
	if repository.ConfigProfile != nil {
		commitMessageTemplate = repository.ConfigProfile.FrogbotConfig.CommitMessageTemplate
		branchNameTemplate = repository.ConfigProfile.FrogbotConfig.BranchNameTemplate
		prTitleTemplate = repository.ConfigProfile.FrogbotConfig.PrTitleTemplate
	}
	customTemplates, err := utils.LoadCustomTemplates(
		commitMessageTemplate,
		branchNameTemplate,
		prTitleTemplate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load custom templates: %w", err)
	}
	return gitManager.SetGitParams(&repository.Params.Git).SetCustomTemplates(customTemplates), nil
}

func (a *AutoPrCmd) prepareRun(run *autoPrRun, gitManager autoPrGitManager) error {
	var err error
	run.fixBranchName, err = gitManager.GenerateFixBranchName(run.baseBranch, run.componentName, run.fixVersion)
	if err != nil {
		return fmt.Errorf("failed to generate fix branch name: %w", err)
	}
	existsInRemote, err := gitManager.BranchExistsInRemote(run.fixBranchName)
	if err != nil {
		return fmt.Errorf("failed to check if fix branch '%s' exists: %w", run.fixBranchName, err)
	}
	if existsInRemote {
		return &ErrAutoPrSkipped{Reason: fmt.Sprintf(
			"a fix branch '%s' already exists for '%s' to version '%s'. If the pull request was previously closed, delete the fix branch to allow a new one to be created.",
			run.fixBranchName, run.componentName, run.fixVersion)}
	}
	run.workspaceDir, err = os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}
	isClean, err := gitManager.IsClean()
	if err != nil {
		return fmt.Errorf("failed to check whether the worktree is clean: %w", err)
	}
	if !isClean {
		return errors.New("auto-pr requires a clean worktree; commit, stash, or remove local changes before running it")
	}
	locate := a.findDescriptorPaths
	if locate == nil {
		locate = findDescriptorPaths
	}
	var isDirect bool
	run.descriptorPaths, run.tech, isDirect, err = locate(run.workspaceDir, run.componentName, run.affectedVersion)
	if err != nil {
		return err
	}
	if len(run.descriptorPaths) == 0 {
		return &ErrAutoPrSkipped{Reason: fmt.Sprintf("component '%s@%s' was not found in the project dependency tree", run.componentName, run.affectedVersion)}
	}
	if run.tech == techutils.NoTech {
		return fmt.Errorf("could not determine package manager for component '%s@%s'", run.componentName, run.affectedVersion)
	}
	if !isDirect {
		return &ErrAutoPrSkipped{Reason: fmt.Sprintf(
			"component '%s@%s' is a transitive dependency; auto-pr only supports direct dependencies",
			run.componentName, run.affectedVersion)}
	}
	return nil
}

func (a *AutoPrCmd) applyFixAndCreatePullRequest(run autoPrRun, repository utils.Repository, client vcsclient.VcsClient, gitManager autoPrGitManager) error {
	if err := gitManager.CreateBranchAndCheckout(run.fixBranchName, false); err != nil {
		return fmt.Errorf("failed to create fix branch '%s': %w", run.fixBranchName, err)
	}
	update := a.runUpdater
	if update == nil {
		update = runUpdater
	}
	if err := update(run.componentName, run.affectedVersion, run.fixVersion, run.tech, true, run.descriptorPaths); err != nil {
		return err
	}
	commitMessage := gitManager.GenerateCommitMessage(run.componentName, run.fixVersion)
	if err := gitManager.AddTrackedAndCommit(commitMessage, run.componentName); err != nil {
		var errNoChanges *utils.ErrNothingToCommit
		if errors.As(err, &errNoChanges) {
			log.Info(err.Error())
			return &ErrAutoPrSkipped{Reason: err.Error()}
		}
		return fmt.Errorf("failed to commit changes: %w", err)
	}
	if err := gitManager.Push(false, run.fixBranchName); err != nil {
		return fmt.Errorf("failed to push branch '%s': %w", run.fixBranchName, err)
	}
	log.Info(fmt.Sprintf("Branch '%s' pushed to origin", run.fixBranchName))

	prTitle := gitManager.GeneratePullRequestTitle(run.componentName, run.fixVersion)
	prBody, extraComments := buildPRBody(repository, run.componentName, run.affectedVersion, run.fixVersion, run.tech, run.descriptorPaths)
	log.Info(fmt.Sprintf("Creating pull request from '%s' to '%s'", run.fixBranchName, run.baseBranch))
	if a.createPullRequest != nil {
		if err := a.createPullRequest(repository, run.fixBranchName, run.baseBranch, prTitle, prBody, extraComments); err != nil {
			return fmt.Errorf("failed to create pull request: %w", err)
		}
	} else if err := createPullRequestWithComments(client, repository, run.fixBranchName, run.baseBranch, prTitle, prBody, extraComments); err != nil {
		return fmt.Errorf("failed to create pull request: %w", err)
	}
	log.Info("Pull request created successfully")
	return nil
}

func validateInputs(componentName, affectedVersion, fixVersion string) error {
	var missing []string
	if componentName == "" {
		missing = append(missing, componentNameEnv)
	}
	if affectedVersion == "" {
		missing = append(missing, affectedVersionEnv)
	}
	if fixVersion == "" {
		missing = append(missing, fixVersionEnv)
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variable(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

func runUpdater(componentName, affectedVersion, fixVersion string, tech techutils.Technology, isDirect bool, descriptorPaths []string) error {
	fixDetails := buildFixDetails(componentName, affectedVersion, fixVersion, tech, isDirect, descriptorPaths)
	updater, supported := securitypkgupdaters.GetCompatiblePackageUpdater(fixDetails)
	if !supported {
		return fmt.Errorf("unsupported technology '%s' for auto-pr", tech)
	}
	log.Info(fmt.Sprintf("Updating '%s' from %s to %s in %d file(s): %v",
		componentName, affectedVersion, fixVersion, len(descriptorPaths), descriptorPaths))
	if err := updater.UpdateDependency(fixDetails); err != nil {
		return fmt.Errorf("failed to update dependency: %w", err)
	}
	log.Info(fmt.Sprintf("Successfully updated '%s' to %s", componentName, fixVersion))
	return nil
}

func buildFixDetails(componentName, affectedVersion, fixVersion string, tech techutils.Technology, isDirect bool, descriptorPaths []string) *securitypkgupdaters.FixDetails {
	return &securitypkgupdaters.FixDetails{
		ImpactedDependencyName:    componentName,
		ImpactedDependencyVersion: affectedVersion,
		SuggestedFixedVersion:     fixVersion,
		IsDirectDependency:        isDirect,
		Technology:                tech,
		Components: []formats.ComponentRow{
			{
				Name:      componentName,
				Version:   affectedVersion,
				Evidences: buildEvidences(descriptorPaths),
			},
		},
	}
}

// buildPRBody reuses the standard fix-PR content produced by scan-repository so auto-pr messages
// stay consistent with the rest of Frogbot.
func buildPRBody(repository utils.Repository, componentName, affectedVersion, fixVersion string, tech techutils.Technology, descriptorPaths []string) (string, []string) {
	writer := repository.OutputWriter
	if writer == nil {
		writer = outputwriter.GetCompatibleOutputWriter(repository.Params.Git.GitProvider, false)
	}
	componentRow := formats.ComponentRow{Name: componentName, Version: affectedVersion}
	rootRow := formats.ComponentRow{Name: repository.Params.Git.RepoName, Version: ""}
	row := formats.VulnerabilityOrViolationRow{
		ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
			ImpactedDependencyName:    componentName,
			ImpactedDependencyVersion: affectedVersion,
			Components:                buildComponentRows(componentName, affectedVersion, descriptorPaths),
		},
		FixedVersions: []string{fixVersion},
		ImpactPaths:   [][]formats.ComponentRow{{rootRow, componentRow}},
		Technology:    tech,
	}
	description, extraComments := utils.GenerateFixPullRequestDetails([]formats.VulnerabilityOrViolationRow{row}, "", writer)
	if commitHash := os.Getenv(commitHashEnv); commitHash != "" {
		description += outputwriter.MarkdownComment(fmt.Sprintf("Scanned commit: %s", commitHash))
	}
	return description, extraComments
}

func createPullRequestWithComments(client vcsclient.VcsClient, repository utils.Repository, sourceBranch, targetBranch, title, body string, extraComments []string) error {
	created, err := client.CreatePullRequestDetailed(context.Background(),
		repository.Params.Git.RepoOwner, repository.Params.Git.RepoName,
		sourceBranch, targetBranch, title, body)
	if err != nil {
		return err
	}
	for _, comment := range extraComments {
		if err = client.AddPullRequestComment(context.Background(),
			repository.Params.Git.RepoOwner, repository.Params.Git.RepoName,
			comment, created.Number); err != nil {
			return fmt.Errorf("failed to post overflow comment: %w", err)
		}
	}
	return nil
}

func buildComponentRows(componentName, affectedVersion string, descriptorPaths []string) []formats.ComponentRow {
	return []formats.ComponentRow{{
		Name:      componentName,
		Version:   affectedVersion,
		Evidences: buildEvidences(descriptorPaths),
	}}
}

func buildEvidences(descriptorPaths []string) []formats.Location {
	evidences := make([]formats.Location, len(descriptorPaths))
	for i, path := range descriptorPaths {
		evidences[i] = formats.Location{File: path}
	}
	return evidences
}
