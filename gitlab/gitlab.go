package gitlab

// Access level constants for GitLab
const (
	AccessLevelNo         = 0
	AccessLevelMinimal    = 5
	AccessLevelGuest      = 10
	AccessLevelPlanner    = 15
	AccessLevelReporter   = 20
	AccessLevelDeveloper  = 30
	AccessLevelMaintainer = 40
	AccessLevelOwner      = 50
	AccessLevelAdmin      = 60
)

// Access level text descriptions
const (
	NoText         = "No access"
	MinimalText    = "Minimal access"
	GuestText      = "Guest"
	PlannerText    = "Planner"
	ReporterText   = "Reporter"
	DeveloperText  = "Developer"
	MaintainerText = "Maintainer"
	OwnerText      = "Owner"
	AdminText      = "Admin"
)
