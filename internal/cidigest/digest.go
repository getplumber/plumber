// Package cidigest computes the CI config content digest the platform and
// the CLI compare to decide whether a branch may reuse the platform
// snapshot's resolved config: a content-keyed (not branch-keyed) identity
// for a project's CI config, made of the root file plus every LOCAL include
// statically reachable from it.
//
// A branch that does not touch its CI config digests equal to the
// snapshot's resolution anchor and evaluates against the snapshot's
// merged_yaml with no extra call; a branch that does change it digests
// differently and gets its own resolution.
//
// This package is a deliberate BYTE-IDENTICAL port of the platform's
// platform/backend/cidigest (monorepo, ADR-0034). The digest is compared
// across the two implementations, so its exact byte construction (see
// Compute) and its traversal rules (see Traverse) must never diverge under
// Version "1". Any change to the construction is a new digest_version;
// versions never mix in one comparison. The golden vectors in
// digest_test.go are the shared pin: they were computed independently of
// either implementation and both must reproduce them.
//
// The package is pure: no network, no API client. Compute hashes a file set
// it is handed; Traverse discovers that file set through a caller-supplied
// fetch function. FetchFromDir supplies the CLI's own file access, reading
// the job checkout from disk.
package cidigest

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// Version is the digest_version paired with every digest this package
// computes ("digest_version: 1"). A caller comparing digests must also
// compare Version; digests computed under different versions are not
// comparable even if they happen to be equal-length hex strings.
const Version = "1"

// prefix is the first bytes of the hashed stream. It disambiguates this
// digest from any other sha256-of-concatenated-things scheme and pins the
// version into the hash itself.
const prefix = "plumber-ci-digest/v1\n"

// absentMarker is written in place of a content hash for a path whose
// content is Absent: a referenced local file that does not exist
// contributes path + NUL + "ABSENT" + NUL.
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

// Compute returns the hex-encoded digest_v1 of files:
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
	// which is exactly the "byte-wise sorted path order" the shared rule
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
