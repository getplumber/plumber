// Package configuration owns .plumber.yaml: the typed control configuration
// structs, loading with unknown-key validation and the v1 to v2 conversion,
// the overlay merge over the shipped default, the required-components
// expression parser, the control registry (ids, categories, providers) and
// the reflected config schema the platform renders forms from.
package configuration
