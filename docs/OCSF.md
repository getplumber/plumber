# OCSF Compliance Finding export

`plumber analyze --ocsf <file>` writes an [OCSF](https://ocsf.io) Compliance
Finding report: a JSON array with one event (`class_uid` 2003) per control,
each carrying an explicit compliance status. Unlike a findings-only export, it
represents the complete compliance posture, so a consumer can tell a genuine
pass from a control that could not be verified. The file is never empty, even
on a degraded scan.

## Status mapping

Each control's `compliance.status_id` comes from Plumber's per-control
evaluation status (the same verdict the `--output` JSON reports):

| Plumber status | `compliance.status` | `compliance.status_id` |
| --- | --- | --- |
| Evaluated, violations found | `Fail` | 3 |
| Evaluated, clean, run healthy | `Pass` | 1 |
| Could not be verified (missing/invalid CI, degraded collection) | `Warning` | 2 |
| Skipped (disabled in `.plumber.yaml` or filtered) | `Skipped` | 99 |

A clean control on a degraded run is `Warning`, never `Pass`. An empty findings
list is never treated as compliant.

## What each event carries

- `compliance.control` is the `.plumber.yaml` control key; `compliance.requirements`
  lists the control's ISSUE codes; `compliance.standards` is `["Plumber"]`.
  Plumber emits its own control identity and leaves framework mapping (CIS,
  NIST, and similar) to the consuming GRC tool.
- On a failure, `remediation.desc` holds the fix guidance and
  `compliance.status_details` lists one line per violation.
- Full structured per-violation records (issue code, file, line, job, message,
  source URL) live under `unmapped.plumber_findings`, OCSF's sanctioned slot for
  vendor fields, so no detail is lost.

## Validating the output

`plumber analyze --ocsf plumber.ocsf.json` writes a JSON array of events. The
[OCSF Schema Server](https://schema.ocsf.io) validates one event object at a
time, so post a single element from the array to its `/api/v2/validate`
endpoint:

```bash
plumber analyze --ocsf plumber.ocsf.json
jq '.[0]' plumber.ocsf.json | curl -sS -X POST https://schema.ocsf.io/api/v2/validate \
  -H "Content-Type: application/json" -d @-
```

The response is a JSON object with `errors` and `warnings` arrays for that
event; repeat with `.[1]`, `.[2]`, and so on to validate every element in the
file. Events declare `metadata.version` 1.8.0, matching the schema server, so a
conformant event returns empty `errors` and `warnings`.
