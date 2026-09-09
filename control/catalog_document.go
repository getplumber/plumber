package control

import (
	"sort"

	"github.com/getplumber/plumber/configuration"
)

// CatalogIssueType is one issue type in the exported catalog: the ISSUE-XXX
// immutable id with the CLI's own wording (title, description, remediation)
// and its owning control, so consumers render the engine's words instead of
// maintaining a copy (#458).
type CatalogIssueType struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	DocURL      string `json:"docUrl"`
	ControlName string `json:"controlName"`
}

// CatalogControl is one control in the exported catalog: the CTRL-XXX
// immutable id, the stable technical name, display metadata, the welded
// config schema when the control has a config block, and the ISSUE codes it
// can emit (#458).
type CatalogControl struct {
	ID             string                             `json:"id"`
	Name           string                             `json:"name"`
	DisplayName    string                             `json:"displayName"`
	Category       string                             `json:"category"`
	Providers      []string                           `json:"providers"`
	Description    string                             `json:"description"`
	RequiresConfig bool                               `json:"requiresConfig"`
	ConfigSchema   *configuration.ControlConfigSchema `json:"configSchema,omitempty"`
	IssueCodes     []string                           `json:"issueCodes"`
}

// CatalogDocument is the whole exported catalog in one versioned envelope:
// what the platform imports through Catalog() and the catalog command
// serializes as JSON (#458). CatalogVersion identifies the document shape;
// consumers are expected to be forward-tolerant to added fields.
type CatalogDocument struct {
	CatalogVersion int                `json:"catalogVersion"`
	CLIVersion     string             `json:"cliVersion"`
	Controls       []CatalogControl   `json:"controls"`
	IssueTypes     []CatalogIssueType `json:"issueTypes"`
}

// Catalog assembles the CLI's whole catalog into one document: the single
// source the platform imports (Go) and the catalog command serializes
// (JSON) so no consumer maintains a divergent copy (#458). cliVersion is
// injected by the caller (cmd passes the build version; tests pass a
// constant) so the document itself stays deterministic.
func Catalog(cliVersion string) CatalogDocument {
	codesByControl := map[string][]string{}
	issueTypes := make([]CatalogIssueType, 0)
	for _, info := range AllCodes() {
		issueTypes = append(issueTypes, CatalogIssueType{
			Code:        string(info.Code),
			Severity:    string(info.Severity),
			Title:       info.Title,
			Description: info.Description,
			Remediation: info.Remediation,
			DocURL:      info.DocURL,
			ControlName: info.ControlName,
		})
		if info.ControlName != "" {
			codesByControl[info.ControlName] = append(codesByControl[info.ControlName], string(info.Code))
		}
	}
	sort.Slice(issueTypes, func(i, j int) bool { return issueTypes[i].Code < issueTypes[j].Code })
	for _, codes := range codesByControl {
		sort.Strings(codes)
	}

	entries := configuration.ControlsCatalog() // already sorted by name
	controls := make([]CatalogControl, 0, len(entries))
	for _, e := range entries {
		c := CatalogControl{
			ID:             e.ID,
			Name:           e.Name,
			DisplayName:    e.DisplayName,
			Category:       e.Category,
			Providers:      e.Providers,
			Description:    e.Description,
			RequiresConfig: e.RequiresConfig,
			IssueCodes:     append([]string{}, codesByControl[e.Name]...),
		}
		if s, ok := configuration.ConfigSchemaFor(e.Name); ok {
			schema := s
			c.ConfigSchema = &schema
		}
		controls = append(controls, c)
	}

	return CatalogDocument{
		CatalogVersion: 1,
		CLIVersion:     cliVersion,
		Controls:       controls,
		IssueTypes:     issueTypes,
	}
}
