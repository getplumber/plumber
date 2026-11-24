package httpcount

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// RateResource is one resource of GitHub's GET /rate_limit answer.
type RateResource struct {
	Limit     int   `json:"limit"`
	Used      int   `json:"used"`
	Remaining int   `json:"remaining"`
	Reset     int64 `json:"reset"`
}

// RateLimit is GET /rate_limit for one credential, read before and after the
// run. A failed read leaves its map nil and says why in the error.
type RateLimit struct {
	Credential string
	Before     map[string]RateResource
	BeforeErr  error
	After      map[string]RateResource
	AfterErr   error
}

// Report is everything the --debug markdown shows about one run.
type Report struct {
	Version     string
	Target      string
	Host        string
	Started     time.Time
	Finished    time.Time
	Credentials []string
	// CredentialNames names the credentials the run knows, by CredentialKey
	// of the Authorization header they are sent with (GITHUB_TOKEN…).
	CredentialNames map[string]string
	RateLimits      []RateLimit
	Snapshot        Snapshot
}

// WriteMarkdown renders the report.
func (r Report) WriteMarkdown(w io.Writer) error {
	var b strings.Builder
	s := r.Snapshot

	b.WriteString("# Plumber GitHub request report\n\n")
	b.WriteString("| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Plumber | %s |\n", cell(r.Version))
	fmt.Fprintf(&b, "| Target | %s |\n", cell(r.Target))
	fmt.Fprintf(&b, "| GitHub API host | %s |\n", cell(r.Host))
	fmt.Fprintf(&b, "| Started | %s |\n", r.Started.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "| Duration | %s |\n", r.Finished.Sub(r.Started).Round(time.Millisecond))
	fmt.Fprintf(&b, "| Credentials | %s |\n\n", cell(strings.Join(r.Credentials, "; ")))

	tokenQuota, anonymous, unmetered, errors := 0, 0, 0, 0
	for _, q := range s.Quotas {
		if q.Anonymous {
			anonymous += q.Requests
		} else {
			tokenQuota += q.Requests
		}
	}
	for _, h := range s.Hosts {
		unmetered += h.Unmetered
		errors += h.Errors
	}
	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "- **%d requests** sent.\n", s.Total())
	fmt.Fprintf(&b, "- %d repeated requests answered from memory, not sent.\n", s.MemoHits)
	fmt.Fprintf(&b, "- **%d** counted by a token's API quota (see *Quotas seen in response headers*).\n", tokenQuota)
	fmt.Fprintf(&b, "- %d anonymous, counted by the 60/hour per-IP quota.\n", anonymous)
	fmt.Fprintf(&b, "- %d outside the API quotas (no `x-ratelimit` headers).\n", unmetered)
	fmt.Fprintf(&b, "- %d without a response (errors).\n\n", errors)

	writeRateLimits(&b, r.RateLimits)
	writeQuotas(&b, s.Quotas, s.Entries, r.CredentialNames)
	writeUnmetered(&b, s.Hosts)
	writeEndpoints(&b, s.Entries)
	writeRepeats(&b, s.Entries)
	writeEntries(&b, s.Entries)

	_, err := io.WriteString(w, b.String())
	return err
}

func writeRateLimits(b *strings.Builder, limits []RateLimit) {
	b.WriteString("## Rate limit (`GET /rate_limit`)\n\n")
	b.WriteString("> Read before and after the run; this endpoint costs no quota. The quota belongs to the account, " +
		"so the change includes every other client using the same account during the run. " +
		"`/advisories` is not in it (observed, not documented: see *Quotas seen in response headers*).\n\n")
	if len(limits) == 0 {
		b.WriteString("_Not read._\n\n")
		return
	}
	for _, rl := range limits {
		fmt.Fprintf(b, "### %s\n\n", rl.Credential)
		if rl.BeforeErr != nil {
			fmt.Fprintf(b, "_Before the run: %s_\n\n", cell(rl.BeforeErr.Error()))
		}
		if rl.AfterErr != nil {
			fmt.Fprintf(b, "_After the run: %s_\n\n", cell(rl.AfterErr.Error()))
		}
		if rl.Before == nil && rl.After == nil {
			continue
		}
		names := make([]string, 0, len(rl.After))
		for name := range rl.Before {
			names = append(names, name)
		}
		for name := range rl.After {
			if _, ok := rl.Before[name]; !ok {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		var rows []string
		for _, name := range names {
			before, after := rl.Before[name], rl.After[name]
			if before.Used == 0 && after.Used == 0 {
				continue
			}
			change := "n/a"
			if rl.Before != nil && rl.After != nil {
				if before.Reset == after.Reset {
					change = fmt.Sprintf("%+d", after.Used-before.Used)
				} else {
					change = "window reset"
				}
			}
			rows = append(rows, fmt.Sprintf("| %s | %d | %d | %d | %s | %d | %s |",
				name, after.Limit, before.Used, after.Used, change, after.Remaining, clock(after.Reset)))
		}
		if len(rows) == 0 {
			b.WriteString("_No resource used._\n\n")
			continue
		}
		b.WriteString("| Resource | Limit | Used before | Used after | Change | Remaining after | Resets |\n")
		b.WriteString("|---|--:|--:|--:|--:|--:|---|\n")
		b.WriteString(strings.Join(rows, "\n"))
		b.WriteString("\n\n")
	}
}

// maxQuotaEndpoints is how many endpoints a quota row lists before "+N more".
const maxQuotaEndpoints = 3

func writeQuotas(b *strings.Builder, quotas []Quota, entries []Entry, names map[string]string) {
	b.WriteString("## Quotas seen in response headers\n\n")
	b.WriteString("> The run's own cost: each row is one quota window (credential, resource, reset), the requests it answered and the endpoints they went to.\n\n")
	if len(quotas) == 0 {
		b.WriteString("_None._\n\n")
		return
	}
	b.WriteString("| Host | Credential | Resource | Limit | Requests | Lowest remaining | Resets | Endpoints |\n")
	b.WriteString("|---|---|---|--:|--:|--:|---|---|\n")
	unknown := map[string]string{}
	for _, q := range quotas {
		fmt.Fprintf(b, "| %s | %s | %s | %d | %d | %d | %s | %s |\n",
			q.Host, cell(credentialName(q, names, unknown)), cell(q.Resource), q.Limit, q.Requests, q.Remaining, clock(q.Reset),
			cell(quotaEndpoints(q, entries)))
	}
	b.WriteString("\n> Observed, not documented: GitHub labels `/advisories` responses `core`, but counts them on a separate counter " +
		"with its own window, which `GET /rate_limit` does not list and which does not take from the main `core` quota. " +
		"The same token can therefore show two `core` rows; the Endpoints column says which is which.\n\n")
}

// credentialName is the row's credential as the run knows it (GITHUB_TOKEN…),
// anonymous, or "token N" in order of first appearance when unnamed.
func credentialName(q Quota, names, unknown map[string]string) string {
	if q.Anonymous {
		return "anonymous"
	}
	if name, ok := names[q.Credential]; ok {
		return name
	}
	if name, ok := unknown[q.Credential]; ok {
		return name
	}
	unknown[q.Credential] = fmt.Sprintf("token %d", len(unknown)+1)
	return unknown[q.Credential]
}

// quotaEndpoints lists the endpoints whose responses fell in q's window,
// most requested first, e.g. "GET /advisories ×20".
func quotaEndpoints(q Quota, entries []Entry) string {
	counts := map[string]int{}
	for _, e := range entries {
		if !e.HasQuota || e.Host != q.Host || e.Resource != q.Resource || e.Credential != q.Credential ||
			max(e.Reset, q.Reset)-min(e.Reset, q.Reset) > resetJitter {
			continue
		}
		counts[e.Method+" "+Template(e.Host, e.Path)]++
	}
	endpoints := make([]string, 0, len(counts))
	for endpoint := range counts {
		endpoints = append(endpoints, endpoint)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if counts[endpoints[i]] != counts[endpoints[j]] {
			return counts[endpoints[i]] > counts[endpoints[j]]
		}
		return endpoints[i] < endpoints[j]
	})
	var parts []string
	for i, endpoint := range endpoints {
		if i == maxQuotaEndpoints {
			parts = append(parts, fmt.Sprintf("+%d more", len(endpoints)-maxQuotaEndpoints))
			break
		}
		parts = append(parts, fmt.Sprintf("`%s` ×%d", endpoint, counts[endpoint]))
	}
	return strings.Join(parts, ", ")
}

func writeUnmetered(b *strings.Builder, hosts map[string]HostStats) {
	b.WriteString("## Outside the API quotas\n\n")
	var rows []string
	for _, h := range sortedKeys(hosts) {
		if n := hosts[h].Unmetered; n > 0 {
			rows = append(rows, fmt.Sprintf("| %s | %d |", h, n))
		}
	}
	if len(rows) == 0 {
		b.WriteString("_None._\n\n")
		return
	}
	b.WriteString("| Host | Requests |\n|---|--:|\n")
	b.WriteString(strings.Join(rows, "\n"))
	b.WriteString("\n\n")
}

type endpointStats struct {
	host, template                 string
	requests, tokenQuota           int
	s2xx, s3xx, s4xx, s5xx, errors int
	total, longest                 time.Duration
}

func writeEndpoints(b *strings.Builder, entries []Entry) {
	b.WriteString("## By endpoint\n\n")
	if len(entries) == 0 {
		b.WriteString("_No request logged._\n\n")
		return
	}
	byKey := map[string]*endpointStats{}
	for _, e := range entries {
		tmpl := Template(e.Host, e.Path)
		key := e.Host + " " + e.Method + " " + tmpl
		st := byKey[key]
		if st == nil {
			st = &endpointStats{host: e.Host, template: e.Method + " " + tmpl}
			byKey[key] = st
		}
		st.requests++
		if e.HasQuota && e.Authenticated {
			st.tokenQuota++
		}
		switch {
		case e.Status == 0:
			st.errors++
		case e.Status >= 500:
			st.s5xx++
		case e.Status >= 400:
			st.s4xx++
		case e.Status >= 300:
			st.s3xx++
		default:
			st.s2xx++
		}
		st.total += e.Duration
		st.longest = max(st.longest, e.Duration)
	}
	stats := make([]*endpointStats, 0, len(byKey))
	for _, st := range byKey {
		stats = append(stats, st)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].requests != stats[j].requests {
			return stats[i].requests > stats[j].requests
		}
		if stats[i].host != stats[j].host {
			return stats[i].host < stats[j].host
		}
		return stats[i].template < stats[j].template
	})
	b.WriteString("| Endpoint | Host | Requests | Token quota | 2xx | 3xx | 4xx | 5xx | Errors | Total time | Longest |\n")
	b.WriteString("|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|\n")
	for _, st := range stats {
		fmt.Fprintf(b, "| `%s` | %s | %d | %d | %d | %d | %d | %d | %d | %s | %s |\n",
			cell(st.template), st.host, st.requests, st.tokenQuota, st.s2xx, st.s3xx, st.s4xx, st.s5xx, st.errors,
			ms(st.total), ms(st.longest))
	}
	b.WriteString("\n")
}

func writeRepeats(b *strings.Builder, entries []Entry) {
	b.WriteString("## Repeated requests\n\n")
	b.WriteString("> The same method and URL sent more than once in the run.\n\n")
	counts := map[string]int{}
	var order []string
	for _, e := range entries {
		key := e.Method + " " + e.Host + e.Target()
		if counts[key] == 0 {
			order = append(order, key)
		}
		counts[key]++
	}
	var repeated []string
	for _, key := range order {
		if counts[key] > 1 {
			repeated = append(repeated, key)
		}
	}
	if len(repeated) == 0 {
		b.WriteString("_None._\n\n")
		return
	}
	sort.SliceStable(repeated, func(i, j int) bool { return counts[repeated[i]] > counts[repeated[j]] })
	b.WriteString("| Times | Request |\n|--:|---|\n")
	for _, key := range repeated {
		fmt.Fprintf(b, "| %d | `%s` |\n", counts[key], cell(key))
	}
	b.WriteString("\n")
}

func writeEntries(b *strings.Builder, entries []Entry) {
	b.WriteString("## All requests\n\n")
	if len(entries) == 0 {
		b.WriteString("_No request logged._\n")
		return
	}
	b.WriteString("| # | Start | Method | Host | Path | Status | Time | Quota | Remaining |\n")
	b.WriteString("|--:|--:|---|---|---|---|--:|---|--:|\n")
	for _, e := range entries {
		status := fmt.Sprint(e.Status)
		if e.Status == 0 {
			status = "error: " + e.Err
		}
		quota, remaining := "none", ""
		switch {
		case e.HasQuota && !e.Authenticated:
			quota, remaining = e.Resource+" anonymous", fmt.Sprint(e.Remaining)
		case e.HasQuota:
			quota, remaining = e.Resource, fmt.Sprint(e.Remaining)
		}
		fmt.Fprintf(b, "| %d | +%s | %s | %s | `%s` | %s | %s | %s | %s |\n",
			e.Seq, ms(e.Offset), e.Method, e.Host, cell(e.Target()), cell(status), ms(e.Duration), cell(quota), remaining)
	}
}

// Target is the request's path with its query.
func (e Entry) Target() string {
	if e.Query == "" {
		return e.Path
	}
	return e.Path + "?" + e.Query
}

// cell keeps a value inside its markdown table cell.
func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s)
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func clock(unix int64) string {
	if unix == 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format("15:04:05Z")
}

func sortedKeys(hosts map[string]HostStats) []string {
	keys := make([]string, 0, len(hosts))
	for h := range hosts {
		keys = append(keys, h)
	}
	sort.Strings(keys)
	return keys
}
