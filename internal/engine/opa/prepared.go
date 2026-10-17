package opa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Compiling a Rego module is the expensive half of an evaluation, and the
// module set never changes within a process while the input changes on
// every call. Each (query, module name, module source) is therefore
// prepared once and the prepared query, which is safe for concurrent use,
// is reused with a fresh input. Keying on the source hash keeps a module
// replaced by a test (same name, other text) from reusing a stale query.
var (
	preparedQueries  sync.Map // preparedKey -> *rego.PreparedEvalQuery
	preparedCompiles atomic.Int64
)

type preparedKey struct {
	query, name, sourceHash string
}

// prepared returns the prepared query for one module, compiling it on the
// first call for that source and reusing it afterwards.
func prepared(ctx context.Context, query, name, source string) (*rego.PreparedEvalQuery, error) {
	sum := sha256.Sum256([]byte(source))
	key := preparedKey{query: query, name: name, sourceHash: hex.EncodeToString(sum[:])}
	if v, ok := preparedQueries.Load(key); ok {
		return v.(*rego.PreparedEvalQuery), nil
	}
	opts := []func(*rego.Rego){
		rego.Query(query),
		rego.Module(name+".rego", source),
	}
	// Only a module that references the shared library (policies/lib)
	// compiles with it: attaching it to every rule made each evaluation
	// compile it about 75 times. A library that does not load fails the
	// module and is never cached.
	if usesLibrary(source) {
		lib, err := libraryModules()
		if err != nil {
			return nil, err
		}
		for _, m := range lib {
			opts = append(opts, rego.ParsedModule(m))
		}
	}
	pq, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	preparedCompiles.Add(1)
	// Two goroutines may compile the same module at once; the one stored
	// first wins, the other compile was equivalent.
	actual, _ := preparedQueries.LoadOrStore(key, &pq)
	return actual.(*rego.PreparedEvalQuery), nil
}
