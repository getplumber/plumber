package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/getplumber/plumber/utils"
	"github.com/spf13/pflag"
)

// analyzeTarget is what `plumber analyze TARGET` resolves the positional
// argument to. It is written into the existing --provider / --project /
// --gitlab-url / --github-url / --branch flags by applyAnalyzeTarget, so the
// rest of the command never learns a positional argument exists.
type analyzeTarget struct {
	provider string // "github" or "gitlab"
	// host is the value for the URL flag: for GitLab the instance URL with
	// its scheme ("https://gitlab.com"); for GitHub the Enterprise host
	// ("ghe.example.com"), and EMPTY for github.com, which is how the
	// --github-url flag spells api.github.com.
	host    string
	project string // "owner/repo" on GitHub, "group/sub/project" on GitLab
	ref     string // branch from a /tree/<ref> suffix, "" when absent
}

const gitlabDotCom = "gitlab.com"

// targetUserinfo matches userinfo in a target URL of any scheme, the scheme
// already lower-cased. sshLikeScheme exempts the two forms whose user is part
// of the address, not a credential ("git" in ssh://git@host/path); their
// userinfo is dropped by ParseGitRemoteURL. A scheme-less target is checked
// separately: an "@" in its host segment is a credential too.
var (
	targetUserinfo = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://[^/]*@`)
	sshLikeScheme  = regexp.MustCompile(`^(?:ssh|git)://`)
	// targetCredential redacts `://userinfo@` wherever the argument is echoed,
	// so no error path can carry a secret even for a URL the parser rejects.
	targetCredential = regexp.MustCompile(`://[^/@\s]+@`)
)

func redactTarget(arg string) string {
	return targetCredential.ReplaceAllString(arg, "://***@")
}

// errTargetCredential never echoes the argument: it holds the credential.
var errTargetCredential = fmt.Errorf("the analyze target carries a credential in its URL; pass the token through GITLAB_TOKEN or GH_TOKEN and give the repository URL alone")

// hostLikeSegment tells a first path segment that names a host
// ("github.com", "gitlab.internal:8080", "localhost") from one that names an
// owner or a group ("getplumber"), so a scheme-less argument can be either a
// URL or a bare owner/repo.
func hostLikeSegment(s string) bool {
	return strings.Contains(s, ".") || strings.Contains(s, ":") || s == "localhost"
}

// parseAnalyzeTarget turns the positional argument of `plumber analyze` into
// a target. providerFlag is the --provider value ("" when unset): it decides
// the host of a bare owner/repo and of an unknown host, and it is an error
// when it contradicts a github.com or gitlab.com host.
//
// Accepted forms: https://github.com/o/r, github.com/o/r, o/r (github.com,
// or gitlab.com under --provider gitlab), https://gitlab.com/g/sub/p,
// gitlab.example.com/g/p, http://gitlab.internal/g/p, git@host:path.git,
// ssh://git@host/path. A .git suffix, a trailing slash, a query string and the
// page suffixes a browser URL carries (/tree/<ref>, /blob/..., /pull/N on
// GitHub; everything from /-/ on GitLab) are dropped; /tree/<ref> becomes the
// ref. Any host other than github.com and gitlab.com is GitLab unless
// --provider github says otherwise.
func parseAnalyzeTarget(arg, providerFlag string) (analyzeTarget, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return analyzeTarget{}, fmt.Errorf("the analyze target is empty; pass a repository such as github.com/owner/repo")
	}
	switch providerFlag {
	case "", "github", "gitlab":
	default:
		return analyzeTarget{}, fmt.Errorf("--provider must be 'github' or 'gitlab' (got %q)", providerFlag)
	}
	// A scheme is case-insensitive (HTTPS://github.com/... pastes happen);
	// lower-casing it first lets one guard and one parser serve every spelling.
	if i := strings.Index(arg, "://"); i >= 0 {
		arg = strings.ToLower(arg[:i]) + arg[i:]
	}
	if targetUserinfo.MatchString(arg) && !sshLikeScheme.MatchString(arg) {
		return analyzeTarget{}, errTargetCredential
	}

	// Cut a query string or fragment: a URL copied from the browser often
	// ends in ?ref_type=heads or #readme.
	if i := strings.IndexAny(arg, "?#"); i >= 0 {
		arg = arg[:i]
	}

	var host, path, scheme string
	switch {
	case strings.Contains(arg, "://") || strings.HasPrefix(arg, "git@"):
		info := utils.ParseGitRemoteURL(strings.TrimSuffix(arg, "/"))
		if info == nil {
			return analyzeTarget{}, fmt.Errorf("%q is not a repository URL; pass https://host/owner/repo, host/owner/repo or owner/repo", redactTarget(arg))
		}
		host, path = info.Host, info.ProjectPath
		if strings.HasPrefix(arg, "http://") {
			scheme = "http"
		}
	default:
		first, rest, _ := strings.Cut(strings.Trim(arg, "/"), "/")
		// user:token@host/path without a scheme: the "@" lands in the host
		// segment, and neither an owner nor a host legitimately contains one.
		if strings.Contains(first, "@") {
			return analyzeTarget{}, errTargetCredential
		}
		if hostLikeSegment(first) {
			host, path = first, rest
		} else {
			path = strings.Trim(arg, "/")
		}
	}
	if scheme == "" {
		scheme = "https"
	}
	host = strings.ToLower(host)
	host = strings.TrimPrefix(host, "www.")
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")

	// Provider from the host, the flag deciding what the host cannot.
	var provider string
	switch {
	case host == githubDotCom:
		if providerFlag == "gitlab" {
			return analyzeTarget{}, fmt.Errorf("--provider gitlab contradicts the github.com target %q", redactTarget(arg))
		}
		provider = "github"
	case host == gitlabDotCom:
		if providerFlag == "github" {
			return analyzeTarget{}, fmt.Errorf("--provider github contradicts the gitlab.com target %q", redactTarget(arg))
		}
		provider = "gitlab"
	case host == "":
		// Bare owner/repo: github.com unless told otherwise.
		if providerFlag == "gitlab" {
			provider, host = "gitlab", gitlabDotCom
		} else {
			provider, host = "github", githubDotCom
		}
	case providerFlag == "github":
		provider = "github"
	default:
		provider = "gitlab"
	}

	target := analyzeTarget{provider: provider}
	segments := strings.Split(path, "/")
	switch provider {
	case "github":
		// owner/repo, then the page suffix the browser added, if any.
		if len(segments) < 2 || segments[0] == "" || segments[1] == "" {
			return analyzeTarget{}, fmt.Errorf("a GitHub target must name owner/repo (got %q)", redactTarget(arg))
		}
		target.project = segments[0] + "/" + segments[1]
		if len(segments) > 3 && segments[2] == "tree" {
			target.ref = strings.Join(segments[3:], "/")
		}
		if host != githubDotCom {
			target.host = host
		}
	default:
		// GitLab: the project path runs up to the /-/ page marker.
		if i := strings.Index(path+"/", "/-/"); i >= 0 {
			rest := strings.TrimPrefix((path + "/")[i+len("/-/"):], "/")
			if ref, ok := strings.CutPrefix(rest, "tree/"); ok {
				target.ref = strings.Trim(ref, "/")
			}
			path = path[:i]
			segments = strings.Split(path, "/")
		}
		if len(segments) < 2 || segments[0] == "" || segments[len(segments)-1] == "" {
			return analyzeTarget{}, fmt.Errorf("a GitLab target must name namespace/project (got %q)", redactTarget(arg))
		}
		target.project = path
		target.host = scheme + "://" + host
	}
	return target, nil
}

// applyAnalyzeTarget writes the target into the analyze flags so provider,
// host, project and branch resolution run exactly as for an explicit
// --project. A coordinate flag already set (on the command line or through
// its PLUMBER_ANALYZE_* variable, which envStringFallback marks as set) that
// disagrees with the target is an error naming both values; one that agrees
// is left alone. An explicit --branch beats the ref carried by the URL.
func applyAnalyzeTarget(fs *pflag.FlagSet, target analyzeTarget) error {
	if fs.Changed("project") {
		if current, _ := fs.GetString("project"); current != target.project {
			return fmt.Errorf("the analyze target names project %q but --project is %q; drop one of them", target.project, current)
		}
	}
	if fs.Changed("provider") {
		if current, _ := fs.GetString("provider"); current != target.provider {
			return fmt.Errorf("the analyze target is a %s repository but --provider %s was given; drop one of them", target.provider, current)
		}
	}
	switch target.provider {
	case "github":
		if fs.Changed("gitlab-url") {
			return fmt.Errorf("the analyze target is a GitHub repository; --gitlab-url does not apply to it")
		}
		if fs.Changed("github-url") {
			current, _ := fs.GetString("github-url")
			if !sameGitHubHost(current, target.host) {
				return fmt.Errorf("the analyze target is on %q but --github-url is %q; drop one of them", displayGitHubHost(target.host), current)
			}
		}
		if err := fs.Set("provider", "github"); err != nil {
			return err
		}
		if target.host != "" && !fs.Changed("github-url") {
			if err := fs.Set("github-url", target.host); err != nil {
				return err
			}
		}
	default:
		if fs.Changed("github-url") {
			return fmt.Errorf("the analyze target is a GitLab repository; --github-url does not apply to it")
		}
		if fs.Changed("gitlab-url") {
			current, _ := fs.GetString("gitlab-url")
			// Host names are case-insensitive; the target host is already lower-cased.
			if !equalIgnoringScheme(strings.ToLower(current), target.host) {
				return fmt.Errorf("the analyze target is on %q but --gitlab-url is %q; drop one of them", target.host, current)
			}
		} else if err := fs.Set("gitlab-url", target.host); err != nil {
			return err
		}
	}
	if !fs.Changed("project") {
		if err := fs.Set("project", target.project); err != nil {
			return err
		}
	}
	if target.ref != "" && !fs.Changed("branch") {
		if err := fs.Set("branch", target.ref); err != nil {
			return err
		}
	}
	return nil
}

// sameGitHubHost compares a --github-url value with a target host, where ""
// (the target's spelling of github.com) matches "", "github.com" and
// "api.github.com", and anything else matches ignoring scheme and slash.
func sameGitHubHost(flagValue, targetHost string) bool {
	v := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(flagValue), "https://"), "http://"), "/")
	if targetHost == "" {
		switch strings.ToLower(v) {
		case "", githubDotCom, "api." + githubDotCom:
			return true
		}
		return false
	}
	return strings.EqualFold(v, targetHost)
}

func displayGitHubHost(targetHost string) string {
	if targetHost == "" {
		return githubDotCom
	}
	return targetHost
}
