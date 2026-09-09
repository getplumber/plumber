package cmd

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var updateCatalog = flag.Bool("update-catalog", false, "rewrite testdata/catalog_golden.json")

// The catalog JSON is the docs site's build input and the platform's
// fallback wire format (#458): its shape is a contract, frozen here.
// Consumers are forward-tolerant, so ADDING fields only needs a golden
// refresh; removing or renaming any is the break this test exists to catch.
func TestCatalogCommandGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := writeCatalogJSON(&buf, "test"); err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("catalog output is not JSON: %v", err)
	}
	if doc["catalogVersion"] != float64(1) || doc["cliVersion"] != "test" {
		t.Fatalf("envelope wrong: %v %v", doc["catalogVersion"], doc["cliVersion"])
	}

	const golden = "testdata/catalog_golden.json"
	if *updateCatalog {
		if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (seed once with -update-catalog): %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Error("catalog JSON diverged from golden. If the change is additive (new field, new control, wording), refresh deliberately: go test ./cmd/ -run TestCatalogCommandGolden -update-catalog. If a field was removed or renamed, that is a consumer break: do not refresh, fix the code.")
	}
}
