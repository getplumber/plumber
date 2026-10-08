package situation_test

import (
	"testing"

	"github.com/getplumber/plumber/internal/ir"
)

// deploysOn reports the state of the job's deploys impact, "" for none.
func deploysOn(t *testing.T, job ir.Job) string {
	t.Helper()
	job.Name = "job"
	if job.Permissions == nil {
		job.Permissions = map[string]any{"contents": "read"}
	}
	return impactOn(t, job)["deploys"].State
}

// TestDeployKubectlAndHelm pins the cluster deploy commands with their
// options before the verb: kubectl apply, create, replace, rollout and set
// image, a kustomize render piped into kubectl apply, helm upgrade and
// helm install. A read (kubectl get, helm template) deploys nothing.
func TestDeployKubectlAndHelm(t *testing.T) {
	for _, line := range []string{
		`kubectl --kubeconfig "$KUBE_CONFIG" apply -f k8s/`,
		`kubectl -n prod apply -k overlays/prod`,
		`kustomize build overlays/prod | kubectl apply -f -`,
		`kubectl rollout restart deployment/web`,
		`kubectl set image deployment/web web=ghcr.io/o/web:1`,
		`helm upgrade --install web ./chart`,
		`helm --kube-context prod install web ./chart`,
	} {
		if got := deploysOn(t, ir.Job{Scripts: []string{line}}); got != "proven" {
			t.Errorf("%q: deploys = %q, want proven", line, got)
		}
	}
	for _, line := range []string{`kubectl get pods`, `helm template web ./chart`, `helm lint ./chart`} {
		if got := deploysOn(t, ir.Job{Scripts: []string{line}}); got != "" {
			t.Errorf("%q: deploys = %q, want none", line, got)
		}
	}
}

// TestDeployPlatformCommands pins the deploy commands of hosting and
// infrastructure tools: terraform apply with options before the verb,
// wrangler, firebase, netlify, vercel, fly, serverless, cdk deploy and
// pulumi up.
func TestDeployPlatformCommands(t *testing.T) {
	for _, line := range []string{
		`terraform -chdir=infra apply -auto-approve`,
		`npx wrangler deploy`,
		`firebase deploy --only hosting`,
		`netlify deploy --prod`,
		`vercel deploy --prod`,
		`flyctl deploy --remote-only`,
		`npx serverless deploy --stage prod`,
		`npx cdk deploy --all`,
		`pulumi up --yes`,
	} {
		if got := deploysOn(t, ir.Job{Scripts: []string{line}}); got != "proven" {
			t.Errorf("%q: deploys = %q, want proven", line, got)
		}
	}
	if got := deploysOn(t, ir.Job{Scripts: []string{`terraform plan`}}); got != "" {
		t.Errorf("terraform plan: deploys = %q, want none", got)
	}
}

// TestDeployActions pins the actions that deploy by definition: the
// bitovi deploy family (any github-actions-deploy-* action), the cloud
// deploy actions, the Pages deployment, and a remote command or copy over
// SSH given a script or a target.
func TestDeployActions(t *testing.T) {
	for _, step := range []ir.Action{
		{Uses: "bitovi/github-actions-deploy-docker-to-ec2@v1.0.1"},
		{Uses: "bitovi/github-actions-deploy-eks-helm@v1"},
		{Uses: "azure/webapps-deploy@v3"},
		{Uses: "Azure/k8s-deploy@v5"},
		{Uses: "aws-actions/amazon-ecs-deploy-task-definition@v2"},
		{Uses: "google-github-actions/deploy-cloudrun@v2"},
		{Uses: "google-github-actions/deploy-appengine@v2"},
		{Uses: "cloudflare/wrangler-action@v3"},
		{Uses: "FirebaseExtended/action-hosting-deploy@v0"},
		{Uses: "actions/deploy-pages@v4"},
		{Uses: "appleboy/ssh-action@v1", With: map[string]any{"script": "cd /srv/app && ./deploy.sh"}},
		{Uses: "appleboy/scp-action@v0.1.7", With: map[string]any{"target": "/srv/app"}},
	} {
		if got := deploysOn(t, ir.Job{Uses: []ir.Action{step}}); got != "proven" {
			t.Errorf("%s: deploys = %q, want proven", step.Uses, got)
		}
	}
	for _, step := range []ir.Action{
		{Uses: "appleboy/ssh-action@v1"},
		{Uses: "cloudflare/wrangler-action@v3", With: map[string]any{"command": "whoami"}},
	} {
		if got := deploysOn(t, ir.Job{Uses: []ir.Action{step}}); got != "" {
			t.Errorf("%s %v: deploys = %q, want none", step.Uses, step.With, got)
		}
	}
}
