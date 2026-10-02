package gitlab

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/getplumber/plumber/internal/ir"
)

const situationCI = `
build:
  stage: build
  script: [make]
  cache:
    key: deps-$CI_COMMIT_REF_SLUG
    paths: [node_modules/]
    policy: pull-push
  artifacts:
    name: dist
    paths: [dist/]
test:
  stage: test
  script: [make test]
  needs: [build]
  cache:
    key: deps-$CI_COMMIT_REF_SLUG
    paths: [node_modules/]
    policy: pull
deploy:
  stage: deploy
  script: [make deploy]
  needs:
    - job: test
    - job: build
      artifacts: true
  dependencies: [build]
  environment:
    name: production
    url: https://example.com
review:
  script: [echo]
  environment: review/$CI_COMMIT_REF_SLUG
lint:
  stage: lint
  script: [make lint]
  cache:
    key:
      files: [package-lock.json, yarn.lock]
    paths: [node_modules/]
crossproject:
  stage: test
  script: [echo]
  needs:
    - project: other/repo
      job: build
      ref: main
package:
  stage: test
  script: [echo]
  needs:
    - build
    - job: test
      artifacts: false
assets:
  stage: build
  script: [make assets]
  cache:
    - key: a
      paths: [a/]
      policy: push
    - key: b
      paths: [b/]
isolated:
  stage: test
  script: [echo]
  needs: [build]
  dependencies: []
downstream:
  stage: test
  script: [echo]
  needs:
    - pipeline: $UPSTREAM_PIPELINE_ID
      job: build
restricted:
  stage: test
  script: [echo]
  needs: [build, test]
  dependencies: [test]
producer_isolated:
  stage: build
  script: [make]
  artifacts:
    paths: [out/]
  needs: [build]
  dependencies: []
mapneed:
  stage: test
  script: [echo]
  needs:
    - job: build
only_tags:
  stage: deploy
  script: [echo]
  only: [tags]
only_refs_map:
  stage: deploy
  script: [echo]
  only:
    refs: [main, merge_requests]
except_branches:
  stage: deploy
  script: [echo]
  except: [branches]
`

// pipelineFromYAML is a test helper that builds a NormalizedPipeline from YAML.
// It unmarshals the YAML into a GitlabCIConf, creates the necessary origin data,
// and calls ToNormalizedPipeline.
func pipelineFromYAML(t *testing.T, yamlStr string) *ir.NormalizedPipeline {
	var conf GitlabCIConf
	if err := yaml.Unmarshal([]byte(yamlStr), &conf); err != nil {
		t.Fatalf("YAML unmarshal failed: %v", err)
	}

	// Build a JobMap with entries for each job found in GitlabJobs
	jobMap := make(map[string]*GitlabPipelineJobData)
	for name := range conf.GitlabJobs {
		jobMap[name] = &GitlabPipelineJobData{Name: name}
	}

	origin := &GitlabPipelineOriginData{
		JobMap:     jobMap,
		MergedConf: &conf,
	}

	return ToNormalizedPipeline("group/project", "main", ".gitlab-ci.yml", origin, nil, nil, nil, nil)
}

func TestEnrichFromMergedConfSituationFields(t *testing.T) {
	p := pipelineFromYAML(t, situationCI)
	byName := map[string]ir.Job{}
	for _, j := range p.Jobs {
		byName[j.Name] = j
	}
	if got := byName["build"].Caches; !reflect.DeepEqual(got, []ir.CacheRef{{Key: "deps-$CI_COMMIT_REF_SLUG", Paths: []string{"node_modules/"}, Mode: "both"}}) {
		t.Errorf("build.Caches = %+v", got)
	}
	if got := byName["test"].Caches; !reflect.DeepEqual(got, []ir.CacheRef{{Key: "deps-$CI_COMMIT_REF_SLUG", Paths: []string{"node_modules/"}, Mode: "restore"}}) {
		t.Errorf("test.Caches = %+v", got)
	}
	if got := byName["build"].Artifacts; !reflect.DeepEqual(got, []ir.ArtifactRef{{Name: "build", Paths: []string{"dist/"}, Mode: "produce"}}) {
		t.Errorf("build.Artifacts = %+v", got)
	}
	if got := byName["test"].Needs; !reflect.DeepEqual(got, []string{"build"}) {
		t.Errorf("test.Needs = %v", got)
	}
	if got := byName["deploy"].Needs; !reflect.DeepEqual(got, []string{"test", "build"}) {
		t.Errorf("deploy.Needs = %v", got)
	}
	// dependencies: is present, so it alone determines what is consumed: needs:
	// contributes nothing, even though it names test and an explicit
	// artifacts: true for build.
	wantConsume := []ir.ArtifactRef{{Name: "build", Mode: "consume"}}
	if got := byName["deploy"].Artifacts; !reflect.DeepEqual(got, wantConsume) {
		t.Errorf("deploy.Artifacts = %+v, want %+v", got, wantConsume)
	}
	if got := byName["deploy"].Environment; got != "production" {
		t.Errorf("deploy.Environment = %q", got)
	}
	if got := byName["review"].Environment; got != "review/$CI_COMMIT_REF_SLUG" {
		t.Errorf("review.Environment = %q", got)
	}
	if got := byName["lint"].Caches; !reflect.DeepEqual(got, []ir.CacheRef{{Key: "files:package-lock.json,yarn.lock", Paths: []string{"node_modules/"}, Mode: "both"}}) {
		t.Errorf("lint.Caches = %+v", got)
	}
	// A cross-project need (carrying project: or pipeline:) does not name a
	// local job, so it must not appear in Needs.
	if got := byName["crossproject"].Needs; got != nil {
		t.Errorf("crossproject.Needs = %v, want nil (cross-project needs are not local jobs)", got)
	}
	// A bare-string need defaults to consuming artifacts; a map need with
	// artifacts: false opts out.
	wantPackageConsume := []ir.ArtifactRef{{Name: "build", Mode: "consume"}}
	if got := byName["package"].Artifacts; !reflect.DeepEqual(got, wantPackageConsume) {
		t.Errorf("package.Artifacts = %+v, want %+v", got, wantPackageConsume)
	}
	// cache: as a list of entries, with policy: push mapped to Mode "save"
	// and the default (pull-push) policy mapped to Mode "both".
	wantAssetsCaches := []ir.CacheRef{
		{Key: "a", Paths: []string{"a/"}, Mode: "save"},
		{Key: "b", Paths: []string{"b/"}, Mode: "both"},
	}
	if got := byName["assets"].Caches; !reflect.DeepEqual(got, wantAssetsCaches) {
		t.Errorf("assets.Caches = %+v, want %+v", got, wantAssetsCaches)
	}
	// dependencies: [] is GitLab's documented way to download no artifacts,
	// overriding the needs default of consuming every needed job's artifacts.
	if got := byName["isolated"].Artifacts; len(got) != 0 {
		t.Errorf("isolated.Artifacts = %+v, want none", got)
	}
	if got := byName["isolated"].Needs; !reflect.DeepEqual(got, []string{"build"}) {
		t.Errorf("isolated.Needs = %v, want [build]", got)
	}
	// A needs: entry carrying a pipeline: key is a parent-pipeline need, not a
	// local job: it must not appear in Needs, and with no dependencies: and no
	// other needs entries, no consume entry for build is recorded either.
	if got := byName["downstream"].Needs; got != nil {
		t.Errorf("downstream.Needs = %v, want nil (pipeline needs are not local jobs)", got)
	}
	if got := byName["downstream"].Artifacts; got != nil {
		t.Errorf("downstream.Artifacts = %v, want nil (no consume for build)", got)
	}
	// dependencies: [test] is present, so it alone determines what is
	// consumed: needs: naming both build and test contributes nothing.
	wantRestrictedConsume := []ir.ArtifactRef{{Name: "test", Mode: "consume"}}
	if got := byName["restricted"].Artifacts; !reflect.DeepEqual(got, wantRestrictedConsume) {
		t.Errorf("restricted.Artifacts = %+v, want %+v", got, wantRestrictedConsume)
	}
	// dependencies: [] means no consume entry, from either source, but the
	// job's own produce entry from artifacts: is unaffected.
	wantProducerIsolated := []ir.ArtifactRef{{Name: "producer_isolated", Paths: []string{"out/"}, Mode: "produce"}}
	if got := byName["producer_isolated"].Artifacts; !reflect.DeepEqual(got, wantProducerIsolated) {
		t.Errorf("producer_isolated.Artifacts = %+v, want %+v", got, wantProducerIsolated)
	}
	// A map-form need ({job: build}) with no artifacts: key and no
	// dependencies: at all still defaults to consuming the needed job's
	// artifacts, the same as the bare-string form.
	if got := byName["mapneed"].Needs; !reflect.DeepEqual(got, []string{"build"}) {
		t.Errorf("mapneed.Needs = %v, want [build]", got)
	}
	wantMapneedConsume := []ir.ArtifactRef{{Name: "build", Mode: "consume"}}
	if got := byName["mapneed"].Artifacts; !reflect.DeepEqual(got, wantMapneedConsume) {
		t.Errorf("mapneed.Artifacts = %+v, want %+v", got, wantMapneedConsume)
	}
	// Legacy only:/except:, string-list form.
	if got := byName["only_tags"].Only; !reflect.DeepEqual(got, []string{"tags"}) {
		t.Errorf("only_tags.Only = %v, want [tags]", got)
	}
	// Legacy only:, map form: flattens to its refs list.
	if got := byName["only_refs_map"].Only; !reflect.DeepEqual(got, []string{"main", "merge_requests"}) {
		t.Errorf("only_refs_map.Only = %v, want [main merge_requests]", got)
	}
	// Legacy except:, string-list form.
	if got := byName["except_branches"].Except; !reflect.DeepEqual(got, []string{"branches"}) {
		t.Errorf("except_branches.Except = %v, want [branches]", got)
	}
}
