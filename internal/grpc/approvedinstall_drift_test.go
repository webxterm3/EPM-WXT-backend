package grpc

import (
	"regexp"
	"strings"
	"testing"
)

// An approval crosses two repositories as JSON, and nothing compiles against
// both sides.
//
// A tag that exists here and not on the agent decodes to the zero value
// there — and for `spent` the zero value is "not spent", which silently
// restores the behaviour the field was added to change: an approval somebody
// used once would go on installing the software for the rest of its window,
// so uninstalling and reinstalling would need nobody's permission.
//
// That is the shape of every bug this file exists for: the new field fails
// closed on an OLD agent, which is correct, but fails OPEN the moment the
// two sides disagree about its name.
func TestTheApprovedInstallContractMatchesTheAgent(t *testing.T) {
	ours := jsonTags(t, readFile(t, "internal/policy/resolve.go"), "type ApprovedInstall struct")
	theirs := jsonTags(t, readAgentSource(t, "internal/apppolicy/policy.go"), "type ApprovedInstall struct")

	// Every field that DECIDES something must be understood by the agent.
	for _, name := range []string{"application", "publisher", "bundle_id", "until", "operation", "spent"} {
		if !ours[name] {
			t.Errorf("the backend no longer sends %q", name)
		}
		if !theirs[name] {
			t.Errorf("the agent no longer reads %q — it will decode to the zero "+
				"value, and for this field that is the old behaviour coming back", name)
		}
	}
}

// jsonTags returns the json tag names on one struct.
func jsonTags(t *testing.T, src, decl string) map[string]bool {
	t.Helper()
	i := strings.Index(src, decl)
	if i < 0 {
		t.Fatalf("%s is gone", decl)
	}
	body := src[i:]
	if j := strings.Index(body, "\n}"); j >= 0 {
		body = body[:j]
	}

	tag := regexp.MustCompile(`json:"([^",]+)`)
	out := map[string]bool{}
	for _, m := range tag.FindAllStringSubmatch(body, -1) {
		out[m[1]] = true
	}
	return out
}
