# Repository graph (draft)

Status: draft, not adopted. [analyze-flow.md](../analyze-flow.md) is the plan: each provider's
policies read its own document, and there is no shared model. This page keeps an alternative for
the analyze steps of the rewrite. Move to it when a policy or the attack paths are simpler to write
on a graph than on the provider document. Two signs that this is happening:

- A policy rebuilds a graph in Rego. Today's `policies/situation/situation.rego` already builds the
  `needs` graph of a pipeline to call `graph.reachable` on it.
- Go walks the document to find attack paths, as today's `control/roles.go` and
  `control/entrytable.go` do.

## The idea

After the Source, Resolve and Sanity stages, `analyze` builds one graph of the analyzed repository
and passes it to Rego next to the provider document. Expected gains:

- The parts both providers have share one input.
- Rego asks reachability questions (`graph.reachable`) and no longer rebuilds edges.
- Attack paths are paths in the graph, so Go and Rego read the same edges.
- An AI that explains a finding or suggests a fix gets one model of the repository, with the file
  and line of each node.

## Shape

The root is the analyzed repository. Each imported action, reusable workflow, include or component
points to a repository node of its own, at a ref. With `--resolve-depth`, the graph covers the
target and the repositories it imports, each with its own facts.

Nodes carry facts about what they stand for, such as "this branch is protected" or "this tag is
immutable". The configuration itself (scripts, `with:`, variables) stays in the provider document,
and a node points to its place there.

### Core, shared by GitHub and GitLab

- Nodes: repository, ref (branch, tag or commit), file.
- Edges: a repository has refs and files; a file imports a ref of another repository.
- Facts: default branch, visibility, archived, branch protected, required reviews, tag protected
  or immutable, ref is a full commit SHA.

### GitHub part

Event triggers, workflows, jobs, steps, calls to actions and reusable workflows, `needs`,
`permissions`, environments and rulesets.

### GitLab part

Pipeline sources, the include tree, jobs, `extends`, `needs`, stages, child pipelines, protected
variables, approval rules and the security policy project.

## Rules

- No pipeline concept in the core. A job exists only in the GitHub and GitLab parts. A core that
  gains jobs turns back into today's `internal/ir`, the shared model that fits neither provider.
- A fact is filled only by the stage that reads it: Sanity for settings, Resolve for imported
  repositories. When that stage didn't run, the fact is absent, so an unknown value never reads as
  false. A control reports "not run" in that case, as `analyze-flow.md` says.
- Building the graph makes no request: it uses what the stages already read.

## Where it would go

- A `graph` package under `internal/` for the core types, filled by `internal/provider/github` and
  `internal/provider/gitlab` after Sanity, and tested in Go like the parsers.
- Rego reads `input.graph` next to the provider document. Its schema in
  `internal/control/policies/schemas/` is a core schema plus a provider extension. Functions in
  `policies/lib` can work on the core (for example "an imported ref is not a SHA"), and provider
  policies read their own part.

## Open questions

- Should the JSON report include the graph, or only the findings built from it?
- Which facts are worth the API requests and token rights they cost?
