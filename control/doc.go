// Package control runs an analysis end to end: it drives the provider data
// collections, projects the collected data and the user's configuration onto
// the Rego engine input, evaluates the policies, and turns findings into
// per-control statuses, the Plumber score, and the catalog of controls and
// issue codes that every other consumer (the terminal, the outputs, the
// platform) reads from.
package control
