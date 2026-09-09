// Package cidigest is a byte-for-byte replica of the Plumber platform's
// platform/backend/cidigest package: the CI config content digest ADR-0034
// rule 1 defines, a content-keyed (not branch-keyed) identity for a
// project's CI config, made of the root file plus every LOCAL include
// statically reachable from it. Digest keying is what lets a branch that
// does not touch its CI config share the default branch's resolved config
// (a cache hit), while a branch that does change it gets its own digest and
// its own resolution.
//
// This package is pure: no DB, no network. Compute hashes a file set that
// is handed to it; Traverse discovers that file set by walking local
// includes through a caller-supplied fetch function, so the CLI (fetching
// from its job checkout) and the platform (fetching through its own
// provider client) share the exact same digest construction and traversal
// rules while each supplies its own file access.
//
// The digest is WIRE-STABLE: it is compared across the CLI and the
// platform (ADR-0034 rule 1, "one shared, versioned rule"), so its exact
// byte construction (see Compute) must never change under Version "1".
// Any change to the construction is a new digest_version; versions never
// mix in one comparison. This package must be kept a literal, deliberate
// port of the platform's package: do not "improve" the construction here
// without a matching change on the platform side and a new Version.
package cidigest

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// Version is the digest_version ADR-0034 rule 1 names ("digest_version: 1").
// A caller comparing digests must also compare Version; digests computed
// under different versions are not comparable even if they happen to be
// equal-length hex strings.
const Version = "1"

// prefix is the first bytes of the hashed stream. It disambiguates this
// digest from any other sha256-of-concatenated-things scheme and pins the
// version into the hash itself (ADR-0034 rule 1's exact formula).
const prefix = "plumber-ci-digest/v1\n"

// absentMarker is written in place of a content hash for a path whose
// content is Absent (ADR-0034 rule 1: "a referenced local file that does
// not exist contributes path + NUL + \"ABSENT\" + NUL").
const absentMarker = "ABSENT"

// Absent is the sentinel value for a files map entry whose content could
// not be obtained: the referenced local include does not exist, or (for
// the root itself) the CI config file is missing on this ref. Traverse
// assigns exactly this value, by reference, for such entries.
//
// Compute recognizes Absent by IDENTITY (same backing array), not by
// content: isAbsent compares the address of the first byte, not the bytes
// themselves. This means a real file whose content happens to consist of
// the exact same bytes as Absent, but was independently allocated (a fresh
// []byte, a copy, a different string literal), is still digested as
// present content, not as ABSENT. Callers building a files map by hand for
// an absent entry must assign this exact value (files[path] = Absent), not
// a copy of it.
var Absent = []byte("cidigest:absent")

// isAbsent reports whether b is exactly the Absent sentinel, by identity.
// See Absent's doc comment for why identity, not content equality, is the
// right check here.
func isAbsent(b []byte) bool {
	return len(b) == len(Absent) && &b[0] == &Absent[0]
}

// Compute returns the hex-encoded digest_v1 of files (ADR-0034 rule 1):
//
//	sha256(
//	  "plumber-ci-digest/v1\n"
//	  + for each path, in byte-wise sorted order:
//	      path + "\x00" + hex(sha256(content)) + "\x00"
//	)
//
// with the ABSENT marker substituted for the hex hash on any entry whose
// content is the Absent sentinel.
//
// files is the complete file set to digest: normally the map Traverse
// returns (the root CI config plus every reachable local include).
// Compute itself does not traverse or interpret includes; it only hashes
// what it is given. Go's map iteration order is randomized, which is
// exactly why the byte-wise sort below exists: without it, the same file
// set could hash differently from one call to the next, breaking the
// wire-stability the digest exists for.
func Compute(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	// Go's string comparison (and sort.Strings) is byte-wise lexicographic,
	// which is exactly the "byte-wise sorted path order" ADR-0034 rule 1
	// specifies: no locale- or case-aware collation involved.
	sort.Strings(paths)

	h := sha256.New()
	h.Write([]byte(prefix))
	for _, p := range paths {
		content := files[p]
		h.Write([]byte(p))
		h.Write([]byte{0})
		if isAbsent(content) {
			h.Write([]byte(absentMarker))
		} else {
			sum := sha256.Sum256(content)
			h.Write([]byte(hex.EncodeToString(sum[:])))
		}
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
