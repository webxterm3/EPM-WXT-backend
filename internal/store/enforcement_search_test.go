package store

import (
	"regexp"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// A search narrows what a tenant may already see. It must never widen it.
//
// The filter is an AND of its top-level keys, so the $or that search adds sits
// BESIDE tenant_id. Hoisting that $or to the top level — the obvious-looking
// simplification — would make "tenant matches OR app name matches" and hand
// one tenant another's enforcement history on any search term.
func TestSearchNarrowsWithinOneTenantAndNeverEscapesIt(t *testing.T) {
	f := enforcementEventFilter(EnforcementEventQuery{TenantID: "t1", Search: "Steam"})

	if f["tenant_id"] != "t1" {
		t.Fatalf("tenant scope is %v, not t1 — a search must not drop it", f["tenant_id"])
	}
	if _, ok := f["$or"]; !ok {
		t.Fatal("no $or: the search term was dropped")
	}
	// If $or were the whole filter, tenant_id would not be a sibling of it.
	if len(f) != 2 {
		t.Errorf("filter has keys %v; want exactly tenant_id AND $or", keysOf(f))
	}
}

// Enforcement activity is mostly file paths, and paths are full of regex
// metacharacters. Unescaped, "C:\Program Files (x86)" is an unbalanced group
// that errors the query, and a bare "." matches every row in the tenant —
// which looks like a search that works until someone trusts it.
func TestTypedTextIsSearchedForLiterally(t *testing.T) {
	for _, term := range []string{
		`C:\Program Files (x86)\Steam`,
		`.`,
		`.*`,
		`Visual Studio Code.app`,
		`a|b`,
	} {
		t.Run(term, func(t *testing.T) {
			f := enforcementEventFilter(EnforcementEventQuery{TenantID: "t1", Search: term})

			clauses, ok := f["$or"].([]bson.M)
			if !ok || len(clauses) == 0 {
				t.Fatal("no search clauses built")
			}
			re, ok := clauses[0]["app_name"].(primitive.Regex)
			if !ok {
				t.Fatalf("app_name clause is %T, not a regex", clauses[0]["app_name"])
			}

			if re.Pattern != regexp.QuoteMeta(term) {
				t.Errorf("pattern %q is not the escaped form of %q", re.Pattern, term)
			}
			// The escaped pattern must compile, and must match the term
			// itself and nothing more interesting.
			compiled, err := regexp.Compile(re.Pattern)
			if err != nil {
				t.Fatalf("escaped pattern does not compile: %v", err)
			}
			if !compiled.MatchString(term) {
				t.Errorf("%q does not match itself", term)
			}
			if term == "." && compiled.MatchString("x") {
				t.Error(`searching for "." matched an unrelated string — it is still a wildcard`)
			}
			if re.Options != "i" {
				t.Errorf("options %q — search should be case-insensitive", re.Options)
			}
		})
	}
}

// The four things somebody has in hand when they ask why their software
// stopped: what it was called, where it lived, and which rule or policy
// decided. Plus the machine, for the fleet-wide view.
func TestSearchCoversTheFieldsSomebodyWouldType(t *testing.T) {
	f := enforcementEventFilter(EnforcementEventQuery{TenantID: "t1", Search: "x"})
	clauses, _ := f["$or"].([]bson.M)

	seen := map[string]bool{}
	for _, c := range clauses {
		for k := range c {
			seen[k] = true
		}
	}
	for _, want := range []string{"app_name", "path", "rule", "policy", "machine_name"} {
		if !seen[want] {
			t.Errorf("search does not cover %q", want)
		}
	}
}

func TestAnEmptySearchDoesNotFilter(t *testing.T) {
	for _, term := range []string{"", "   ", "\t\n"} {
		f := enforcementEventFilter(EnforcementEventQuery{TenantID: "t1", Search: term})
		if _, ok := f["$or"]; ok {
			t.Errorf("a blank search (%q) built a filter — it would match nothing "+
				"and read as an empty history", term)
		}
	}
}

func TestOneMachineStaysOneMachineWhenSearching(t *testing.T) {
	f := enforcementEventFilter(EnforcementEventQuery{
		TenantID: "t1", AgentID: "agent-7", Search: "Steam",
	})
	if f["agent_id"] != "agent-7" {
		t.Error("searching on a machine's page widened the list to the whole fleet")
	}
}

func keysOf(m bson.M) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
