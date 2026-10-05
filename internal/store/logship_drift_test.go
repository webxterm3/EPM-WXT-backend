package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// agentRepo is where the agent source sits relative to this package when both
// repositories are checked out side by side.
const agentRepo = "../../../wxt-agent"

// The command id and the payload keys are a contract between two repositories
// that no compiler checks. The last two times a constant drifted like this —
// the launchd label and the Windows service name — self-update failed silently
// on both platforms for weeks, so these read the agent's source directly.

func TestLogShipCommandIDMatchesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/agent/logship.go")

	const want = `LogShipCommandID = "__vsay_logship__"`
	if !strings.Contains(src, want) {
		t.Fatalf("the agent no longer defines %s — settings pushed from the portal would be ignored", want)
	}
}

// Every key this backend sends must exist as a json tag on the agent's config
// struct. A key the agent does not recognise is not an error there: the field
// stays at its zero value, so a rename would quietly disable that setting on
// the whole fleet.
func TestAgentPayloadKeysExistOnTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/config/config.go")

	start := strings.Index(src, "type LogShippingConfig struct {")
	if start < 0 {
		t.Fatal("the agent no longer has a LogShippingConfig")
	}
	end := strings.Index(src[start:], "\n}")
	if end < 0 {
		t.Fatal("could not read the agent's LogShippingConfig")
	}
	block := src[start : start+end]

	payload := LogShippingConfig{}.AgentPayload()
	for key := range payload {
		if !strings.Contains(block, `json:"`+key+`"`) &&
			!strings.Contains(block, `json:"`+key+`,omitempty"`) {
			t.Errorf("we send %q but the agent has no json tag for it — that setting would silently do nothing", key)
		}
	}
}

// The reverse direction: a setting the agent understands but we never send
// stays at its zero value forever, which is invisible from the portal.
func TestEveryAgentSettingIsSent(t *testing.T) {
	payload := LogShippingConfig{}.AgentPayload()

	// Every field on our own struct must appear in the payload, since ours is
	// the shape the portal edits.
	typ := reflect.TypeOf(LogShippingConfig{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		if _, ok := payload[name]; !ok {
			t.Errorf("%s is stored but never sent to the agent, so setting it has no effect", name)
		}
	}
}

// The payload has to survive JSON, which is how it reaches the agent.
func TestAgentPayloadIsSerialisable(t *testing.T) {
	cfg := LogShippingConfig{
		Enabled: true, SystemLogs: true, Websites: true,
		IntervalSeconds: 60, DailyBudgetMB: 512, BackfillHours: 6,
		WindowsChannels: []string{"Security"},
	}

	data, err := json.Marshal(cfg.AgentPayload())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back["system_logs"] != true {
		t.Errorf("system_logs = %v", back["system_logs"])
	}
	if back["daily_budget_mb"] != float64(512) {
		t.Errorf("daily_budget_mb = %v", back["daily_budget_mb"])
	}
}

// readAgentFile loads a file from the agent repository, skipping when it is
// not checked out beside this one. Skipping states the precondition rather
// than passing quietly and pretending the contract was verified.
func readAgentFile(t *testing.T, rel string) string {
	t.Helper()

	path := filepath.Join(agentRepo, rel)
	data, err := os.ReadFile(path) // #nosec G304 -- fixed test fixture path
	if err != nil {
		t.Skipf("agent source not available at %s — this contract is unverified in this checkout", path)
	}
	return string(data)
}
