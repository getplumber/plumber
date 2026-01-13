package gitlab

import (
	"time"
)

// StringOrSlice is a type that can unmarshal from either a string or a slice of strings
// This is needed for GitLab CI fields like pull_policy that support both formats:
//   - pull_policy: "always"
//   - pull_policy: [if-not-present, always]
//   - pull_policy:
//   - if-not-present
//   - always
type StringOrSlice []string

// UnmarshalYAML implements yaml.v2 Unmarshaler interface
func (s *StringOrSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try to unmarshal as a single string first
	var single string
	if err := unmarshal(&single); err == nil {
		// Handle null/empty YAML values - don't create slice with empty string
		if single == "" {
			*s = nil
			return nil
		}
		*s = []string{single}
		return nil
	}

	// Otherwise, unmarshal as a slice of strings
	var slice []string
	if err := unmarshal(&slice); err != nil {
		return err
	}
	*s = slice
	return nil
}

// Data of a GitLab group
type Group struct {
	IdOnPlatform      int       `json:"idOnPlatform" validate:"required,number"`
	GroupIdOnPlatform int       `json:"groupIdOnPlatform" validate:"number"`
	Path              string    `json:"path" validate:"required,max=300"`
	Name              string    `json:"name" validate:"required,max=300"`
	Visibility        string    `json:"visibility" validate:"required,max=50"`
	CreatedAt         time.Time `json:"createdAt"`
}

// Data of a GitLab project
type Project struct {
	IdOnPlatform        int       `json:"idOnPlatform" validate:"required,number"`
	GroupIdOnPlatform   int       `json:"groupIdOnPlatform" validate:"required,number"`
	Path                string    `json:"path" validate:"required,max=300"`
	Name                string    `json:"name" validate:"required,max=300"`
	Visibility          string    `json:"visibility" validate:"required,max=50"`
	DefaultBranch       string    `json:"defaultBranch" validate:"max=100"`
	CiConfPath          string    `json:"ciConfPath" validate:"required,max=100"`
	LastActivityAt      time.Time `json:"lastActivityAt" validate:"required"`
	Archived            bool      `json:"archived"`
	LatestHeadCommitSha string    `json:"latestHeadCommitSha"`
	IsCatalogResource   bool      `json:"isCatalogResource"`
	//Note: IsOfficialCatalogResource is not returned by gitlab, we set it ourselves
	IsOfficialCatalogResource bool              `json:"isOfficialCatalogResource"`
	Languages                 []ProjectLanguage `json:"languages"`
	CreatedAt                 time.Time         `json:"createdAt" validate:"required"`
}

// ProjectLanguage represents a programming language used in a project
type ProjectLanguage struct {
	Name  string  `json:"name"`
	Share float64 `json:"share"`
}

// Data of a GitLab branch
type Branch struct {
	Name string `json:"name"`
}

type BranchProtection struct {
	ProtectionPattern         string                        `json:"protectionPattern"`
	AllowForcePush            bool                          `json:"allowForcePush"`
	CodeOwnerApprovalRequired bool                          `json:"codeOwnerApprovalRequired"`
	MinPushAccessLevel        int                           `json:"minPushAccessLevel"`
	MinMergeAccessLevel       int                           `json:"minMergeAccessLevel"`
	PushAccessLevels          []BranchProtectionAccessLevel `json:"pushAccessLevels"`
	MergeAccessLevels         []BranchProtectionAccessLevel `json:"mergeAccessLevels"`
}

type BranchProtectionAccessLevel struct {
	AccessLevel            int    `json:"accessLevel"`
	AccessLevelDescription string `json:"accessLevelDescription"`
}

type SecurityPolicyProject struct {
	Id       int    `json:"id"`
	Name     string `json:"name"`
	FullPath string `json:"fullPath"`
}

type IncludeOriginWithoutRef struct {
	Location string `json:"location"`
	Type     string `json:"type"`
	Project  string `json:"project"`
}

type IncludeOrigin struct {
	IncludeOriginWithoutRef
	Raw string `json:"raw"`
	Ref string `json:"ref"`
}

// Data of Gitlab projects and groups variables
type CICDVariable struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Environment string `json:"environment"`
	Protected   bool   `json:"protected"`
	Masked      bool   `json:"masked"`
	Hidden      bool   `json:"hidden"`
	Value       string `json:"value"`
}

type CICatalogResource struct {
	ID                  string                     `json:"id"`
	Name                string                     `json:"name"`
	Description         string                     `json:"description"`
	Topics              []string                   `json:"topics"`
	VerificationLevel   string                     `json:"verificationLevel"`
	VisibilityLevel     string                     `json:"visibilityLevel"`
	StarCount           int                        `json:"starCount"`
	Icon                string                     `json:"icon"`
	FullPath            string                     `json:"fullPath"`
	Last30DayUsageCount int                        `json:"last30DayUsageCount"`
	LatestReleasedAt    string                     `json:"latestReleasedAt"`
	WebPath             string                     `json:"webPath"`
	Versions            []CICatalogResourceVersion `json:"versions"`
}

type CICatalogResourceVersion struct {
	Name       string        `json:"name"`
	Path       string        `json:"path"`
	Components []CIComponent `json:"components"`
}

type CIComponent struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	IncludePath string `json:"includePath"`
}

type CICDVariableSource struct {
	ID         int            `json:"id"`
	Name       string         `json:"name"`
	Path       string         `json:"path"`
	Visibility string         `json:"visibility"`
	Type       string         `json:"type"`
	All        []CICDVariable `json:"all"`
}

type CICDVariableConf struct {
	Path        string `json:"path" validate:"required,max=300"`
	Name        string `json:"name" validate:"required,max=300"`
	Environment string `json:"environment" validate:"required,max=100"`
	Protected   bool   `json:"protected"`
	Masked      bool   `json:"masked"`
}

// GitLab CI Configuration
type GitlabCIConf struct {
	Image           interface{}            `yaml:"image,omitempty"`
	GlobalVariables map[string]interface{} `yaml:"variables,omitempty"`
	Stages          []string               `yaml:"stages,omitempty"`
	BeforeScript    interface{}            `yaml:"before_script,omitempty"`
	AfterScript     interface{}            `yaml:"after_script,omitempty"`
	DefaultScript   interface{}            `yaml:"script,omitempty"`
	Default         CIConfDefault          `yaml:"default,omitempty"`
	Spec            interface{}            `yaml:"spec,omitempty"`

	Include    []interface{}          `yaml:"include,omitempty"` // Can be list of string or list of include
	GitlabJobs map[string]interface{} `yaml:",inline"`           // Can be a string or a map[string]GitlabJob
	Workflow   interface{}            `yaml:"workflow,omitempty"`
	Cache      interface{}            `yaml:"cache,omitempty"`
}

type GitlabJob struct {
	Script       interface{}            `yaml:"script,omitempty"`        // Can be both multi lines or one literal block scalar
	BeforeScript interface{}            `yaml:"before_script,omitempty"` // Can be both multi lines or one literal block scalar
	AfterScript  interface{}            `yaml:"after_script,omitempty"`  // Can be both multi lines or one literal block scalar
	Stage        string                 `yaml:"stage,omitempty"`
	Image        interface{}            `yaml:"image,omitempty"`
	Services     interface{}            `yaml:"services,omitempty"` // Can be both a list of string or a list of Serive
	Only         interface{}            `yaml:"only,omitempty"`
	Except       interface{}            `yaml:"except,omitempty"`
	Variables    map[string]interface{} `yaml:"variables,omitempty"`
	Cache        interface{}            `yaml:"cache,omitempty"`
	Dependencies interface{}            `yaml:"dependencies,omitempty"`
	Needs        interface{}            `yaml:"needs,omitempty"`
	Rules        interface{}            `yaml:"rules,omitempty"`
	Artifacts    interface{}            `yaml:"artifacts,omitempty"`
	Environment  interface{}            `yaml:"environment,omitempty"`
	When         interface{}            `yaml:"when,omitempty"`
	AllowFailure interface{}            `yaml:"allow_failure,omitempty"`
	Extends      interface{}            `yaml:"extends,omitempty"`
}

type Image struct {
	Name       string        `yaml:"name,omitempty"`
	Entrypoint []string      `yaml:"entrypoint,omitempty"`
	PullPolicy StringOrSlice `yaml:"pull_policy,omitempty"`
}

type Service struct {
	Name       string      `yaml:"name,omitempty"`
	Alias      string      `yaml:"alias,omitempty"`
	Entrypoint string      `yaml:"entrypoint,omitempty"`
	Image      interface{} `yaml:"image,omitempty"`
	Command    string      `yaml:"command,omitempty"`
}

type Rule struct {
	// NOTE: this type must be updated if we need to use it !
	// See https://docs.gitlab.com/ee/ci/yaml/#rules
	If           string   `yaml:"if"`
	ChangesFrom  []string `yaml:"changes"`
	When         string   `yaml:"when"`
	AllowFailure bool     `yaml:"allow_failure"`
}

type Cache struct {
	// NOTE: this type must be verified if we need to use it !
	// See https://docs.gitlab.com/ee/ci/yaml/#rules
	Key       interface{} `yaml:"key,omitempty"`
	Paths     []string    `yaml:"paths,omitempty"`
	Policy    string      `yaml:"policy,omitempty"`
	When      string      `yaml:"when,omitempty"`
	Untracked bool        `yaml:"untracked,omitempty"`
}

type Artifacts struct {
	// NOTE: this type must be verified if we need to use it !
	// See https://docs.gitlab.com/ee/ci/yaml/#rules
	Paths     []string `yaml:"paths,omitempty"`
	When      string   `yaml:"when,omitempty"`
	Name      string   `yaml:"name,omitempty"`
	Untracked bool     `yaml:"untracked,omitempty"`
}

type Environment struct {
	// NOTE: this type must be verified if we need to use it !
	// See https://docs.gitlab.com/ee/ci/yaml/#rules
	Name map[string]string `yaml:",inline"`
	URL  string            `yaml:"url,omitempty"`
}

// Common struct for GitLab members (both project and group members)
type GitlabMemberInfo struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`          // GitLab username (@username)
	DisplayedName string `json:"displayedName"` // GitLab display name (e.g., "John Doe")
	Email         string `json:"email"`
	AvatarURL     string `json:"avatarUrl"`
	AccessLevel   int    `json:"accessLevel"`
}

type Resources struct {
	Limits *Resource `yaml:"limits,omitempty"`
}

type Resource struct {
	CPU    int `yaml:"cpu,omitempty"`
	Memory int `yaml:"memory,omitempty"`
}

type Only struct {
	// NOTE: this type must be verified if we need to use it !
	// See https://docs.gitlab.com/ee/ci/yaml/#rules
	Refs      []string          `yaml:"refs,omitempty"`
	Kinds     []string          `yaml:"kinds,omitempty"`
	Variables map[string]string `yaml:"variables,omitempty"`
}

type Except struct {
	// NOTE: this type must be verified if we need to use it !
	// See https://docs.gitlab.com/ee/ci/yaml/#rules
	Refs      []string          `yaml:"refs,omitempty"`
	Kinds     []string          `yaml:"kinds,omitempty"`
	Variables map[string]string `yaml:"variables,omitempty"`
}

type Workflow struct {
	// NOTE: this type must be verified if we need to use it !
	// See https://docs.gitlab.com/ee/ci/yaml/#rules
	Rules interface{} `yaml:"rules,omitempty"`
}

type Include struct {
	Local    string      `yaml:"local,omitempty"`
	Project  string      `yaml:"project,omitempty"`
	Remote   string      `yaml:"remote,omitempty"`
	Template string      `yaml:"template,omitempty"`
	File     interface{} `yaml:"file,omitempty"` // Slice of string or string
	Ref      string      `yaml:"ref,omitempty"`
}

type CIConfVariable struct {
	Description string   `yaml:"description,omitempty"`
	Value       string   `yaml:"value,omitempty"`
	Options     []string `yaml:"options,omitempty"`
}

type CIConfDefault struct {
	Image interface{} `yaml:"image,omitempty"`
}
