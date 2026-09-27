// Package cidigest computes the content digest of a project's CI
// configuration as seen from its checkout (the entry file and every local
// include it reaches), so a linked run and the platform can tell whether
// they are looking at the same configuration.
package cidigest
