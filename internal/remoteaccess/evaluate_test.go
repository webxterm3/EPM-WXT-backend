package remoteaccess

import (
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

func machine() *store.Machine {
	return &store.Machine{AgentID: "agent-1", TenantID: "t1", GroupIDs: []string{"support"}}
}

func policy(name, scope string) *store.RemoteAccessPolicy {
	return &store.RemoteAccessPolicy{
		ID: primitive.NewObjectID(), Name: name, TenantID: "t1", Enabled: true,
		Scope:         store.PolicyScope{Kind: scope},
		AllowAttended: true, AllowUnattended: true, AllowTerminal: true,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func request() Request {
	return Request{
		AccessKind: store.AccessAttended, Role: "company_admin", Username: "admin",
		GroupIDs: []string{"support"}, Reason: "ticket 123",
		RecordingAvailable: true,
		Now:                time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC), // a Wednesday
	}
}

// This feature arrives in an upgrade to deployments that already work.
// Appearing and locking everybody out of their own machines would be the
// wrong default by a wide margin.
func TestNoPolicyAllows(t *testing.T) {
	d := Evaluate(machine(), nil, request())
	if !d.Allowed {
		t.Fatalf("refused with no policy configured: %s", d.Reason)
	}
	// Consent is the product's existing behaviour for attended sessions and
	// must not quietly switch off.
	if !d.RequireConsent {
		t.Error("consent was not required for an attended session with no policy")
	}
}

func TestDisabledPolicyIsIgnored(t *testing.T) {
	p := policy("off", store.PolicyScopeTenant)
	p.Enabled = false
	p.AllowAttended = false

	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, request()); !d.Allowed {
		t.Errorf("a disabled policy still refused: %s", d.Reason)
	}
}

func TestAccessKindCanBeRefused(t *testing.T) {
	p := policy("no-unattended", store.PolicyScopeTenant)
	p.AllowUnattended = false

	req := request()
	req.AccessKind = store.AccessUnattended

	d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, req)
	if d.Allowed {
		t.Fatal("unattended access was permitted by a policy that forbids it")
	}
	// A refusal has to say what was refused and by what, or nobody can act on it.
	if !strings.Contains(d.Reason, "Unattended") || !strings.Contains(d.Reason, "no-unattended") {
		t.Errorf("refusal does not identify the access kind and policy: %q", d.Reason)
	}

	// The other kinds are untouched.
	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, request()); !d.Allowed {
		t.Errorf("attended access was refused by an unattended-only restriction: %s", d.Reason)
	}
}

func TestRoleRestriction(t *testing.T) {
	p := policy("admins-only", store.PolicyScopeTenant)
	p.AllowedRoles = []string{"super_admin"}

	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, request()); d.Allowed {
		t.Error("a company_admin connected under a super_admin-only policy")
	}

	req := request()
	req.Role = "super_admin"
	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, req); !d.Allowed {
		t.Errorf("the permitted role was refused: %s", d.Reason)
	}
}

// Group restriction is what makes the Entra sync pay off: an operator writes
// "only the Support team" once, and membership is maintained upstream.
func TestGroupRestriction(t *testing.T) {
	p := policy("support-only", store.PolicyScopeTenant)
	p.AllowedGroupIDs = []string{"support-team"}

	outsider := request()
	outsider.GroupIDs = []string{"finance"}
	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, outsider); d.Allowed {
		t.Error("somebody outside the permitted groups connected")
	}

	member := request()
	member.GroupIDs = []string{"finance", "support-team"}
	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, member); !d.Allowed {
		t.Errorf("a member of the permitted group was refused: %s", d.Reason)
	}
}

func TestTimeWindowBusinessHours(t *testing.T) {
	p := policy("business-hours", store.PolicyScopeTenant)
	p.TimeWindows = []store.TimeWindow{{
		Days:        []int{1, 2, 3, 4, 5}, // Mon–Fri
		StartMinute: 9 * 60,
		EndMinute:   18 * 60,
		Timezone:    "UTC",
	}}

	cases := []struct {
		name string
		when time.Time
		want bool
	}{
		{"Wednesday mid-morning", time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC), true},
		{"Wednesday just before open", time.Date(2026, 10, 7, 8, 59, 0, 0, time.UTC), false},
		{"Wednesday at open", time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC), true},
		{"Wednesday at close", time.Date(2026, 10, 7, 18, 0, 0, 0, time.UTC), false},
		{"Wednesday just before close", time.Date(2026, 10, 7, 17, 59, 0, 0, time.UTC), true},
		{"Saturday mid-morning", time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC), false},
		{"Sunday mid-morning", time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := request()
			req.Now = c.when
			if got := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, req).Allowed; got != c.want {
				t.Errorf("allowed = %v, want %v", got, c.want)
			}
		})
	}
}

// "Business hours" is a statement about where the people are. A support team
// in Pune working to a window set in UTC would find it opened at half past two
// in the morning.
func TestTimeWindowUsesItsOwnTimezone(t *testing.T) {
	p := policy("india-hours", store.PolicyScopeTenant)
	p.TimeWindows = []store.TimeWindow{{
		StartMinute: 9 * 60, EndMinute: 18 * 60, Timezone: "Asia/Kolkata",
	}}

	// 05:00 UTC is 10:30 in Kolkata — inside the window.
	inside := request()
	inside.Now = time.Date(2026, 10, 7, 5, 0, 0, 0, time.UTC)
	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, inside); !d.Allowed {
		t.Errorf("10:30 local was refused: %s", d.Reason)
	}

	// 16:00 UTC is 21:30 in Kolkata — outside.
	outside := request()
	outside.Now = time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, outside); d.Allowed {
		t.Error("21:30 local was permitted by a 09:00–18:00 window")
	}
}

// A night shift crosses midnight. Comparing it as a simple range would make it
// match nothing at all — exactly when somebody is on call.
func TestOvernightWindow(t *testing.T) {
	p := policy("night-shift", store.PolicyScopeTenant)
	p.TimeWindows = []store.TimeWindow{{
		StartMinute: 22 * 60, EndMinute: 6 * 60, Timezone: "UTC",
	}}

	cases := map[string]struct {
		when time.Time
		want bool
	}{
		"23:00": {time.Date(2026, 10, 7, 23, 0, 0, 0, time.UTC), true},
		"02:00": {time.Date(2026, 10, 7, 2, 0, 0, 0, time.UTC), true},
		"05:59": {time.Date(2026, 10, 7, 5, 59, 0, 0, time.UTC), true},
		"06:00": {time.Date(2026, 10, 7, 6, 0, 0, 0, time.UTC), false},
		"12:00": {time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC), false},
		"21:59": {time.Date(2026, 10, 7, 21, 59, 0, 0, time.UTC), false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			req := request()
			req.Now = c.when
			if got := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, req).Allowed; got != c.want {
				t.Errorf("allowed = %v, want %v", got, c.want)
			}
		})
	}
}

// An unloadable zone must not silently stop restricting anything.
func TestUnknownTimezoneFallsBackRatherThanMatchingEverything(t *testing.T) {
	p := policy("typo", store.PolicyScopeTenant)
	p.TimeWindows = []store.TimeWindow{{
		StartMinute: 9 * 60, EndMinute: 18 * 60, Timezone: "Mars/Olympus_Mons",
	}}

	req := request()
	req.Now = time.Date(2026, 10, 7, 22, 0, 0, 0, time.UTC) // outside, in UTC
	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, req); d.Allowed {
		t.Error("a window with an unloadable timezone stopped restricting anything")
	}
}

// Several windows are alternatives: weekdays OR weekend mornings.
func TestAnyWindowMatching_IsEnough(t *testing.T) {
	p := policy("split", store.PolicyScopeTenant)
	p.TimeWindows = []store.TimeWindow{
		{Days: []int{1, 2, 3, 4, 5}, StartMinute: 9 * 60, EndMinute: 18 * 60, Timezone: "UTC"},
		{Days: []int{6}, StartMinute: 10 * 60, EndMinute: 13 * 60, Timezone: "UTC"},
	}

	saturday := request()
	saturday.Now = time.Date(2026, 10, 10, 11, 0, 0, 0, time.UTC)
	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, saturday); !d.Allowed {
		t.Errorf("Saturday 11:00 was refused despite a matching window: %s", d.Reason)
	}
}

// A policy that says sessions are recorded has to mean it — letting an
// unrecorded one through would make every later audit a lie.
func TestRecordingRequirementRefusesWhenStorageIsMissing(t *testing.T) {
	p := policy("must-record", store.PolicyScopeTenant)
	p.RequireRecording = true

	req := request()
	req.RecordingAvailable = false

	d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, req)
	if d.Allowed {
		t.Fatal("an unrecorded session was permitted by a policy that requires recording")
	}
	if !strings.Contains(d.Reason, "recording") {
		t.Errorf("refusal does not mention recording: %q", d.Reason)
	}

	req.RecordingAvailable = true
	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, req); !d.Allowed {
		t.Errorf("refused despite recording being available: %s", d.Reason)
	}
}

func TestReasonRequirement(t *testing.T) {
	p := policy("needs-reason", store.PolicyScopeTenant)
	p.RequireReason = true

	for _, reason := range []string{"", "   "} {
		req := request()
		req.Reason = reason
		if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, req); d.Allowed {
			t.Errorf("connected with reason %q", reason)
		}
	}
	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, request()); !d.Allowed {
		t.Errorf("refused despite a reason being given: %s", d.Reason)
	}
}

// Machine beats group beats tenant, and the answer must not depend on the
// order the database happened to return rows in.
func TestMostSpecificPolicyWins(t *testing.T) {
	tenant := policy("tenant-blocks", store.PolicyScopeTenant)
	tenant.AllowAttended = false

	group := policy("group-allows", store.PolicyScopeGroup)
	group.Scope.GroupIDs = []string{"support"}

	machinePol := policy("machine-blocks", store.PolicyScopeMachine)
	machinePol.Scope.AgentIDs = []string{"agent-1"}
	machinePol.AllowAttended = false

	d := Evaluate(machine(), []*store.RemoteAccessPolicy{tenant, group, machinePol}, request())
	if d.Allowed || d.PolicyName != "machine-blocks" {
		t.Errorf("decided by %q (allowed=%v), want the machine-scoped policy", d.PolicyName, d.Allowed)
	}

	// Without the machine one, the group policy should beat the tenant's.
	d = Evaluate(machine(), []*store.RemoteAccessPolicy{tenant, group}, request())
	if !d.Allowed || d.PolicyName != "group-allows" {
		t.Errorf("decided by %q (allowed=%v), want the group policy", d.PolicyName, d.Allowed)
	}

	// Order of the slice must make no difference.
	reversed := Evaluate(machine(), []*store.RemoteAccessPolicy{group, tenant}, request())
	if reversed.PolicyName != d.PolicyName {
		t.Errorf("a different slice order decided differently: %q vs %q", reversed.PolicyName, d.PolicyName)
	}
}

func TestPolicyForAnotherMachineIsIgnored(t *testing.T) {
	other := policy("elsewhere", store.PolicyScopeMachine)
	other.Scope.AgentIDs = []string{"agent-999"}
	other.AllowAttended = false

	if d := Evaluate(machine(), []*store.RemoteAccessPolicy{other}, request()); !d.Allowed {
		t.Errorf("a policy aimed at another machine refused this one: %s", d.Reason)
	}
}

// The conditions have to reach the caller, which is what actually enforces them.
func TestConditionsAreReturnedWithAnAllow(t *testing.T) {
	p := policy("strict", store.PolicyScopeTenant)
	p.RequireConsent = true
	p.RequireRecording = true
	p.MaxSessionMinutes = 30

	d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, request())
	if !d.Allowed {
		t.Fatalf("refused: %s", d.Reason)
	}
	if !d.RequireConsent || !d.RequireRecording || d.MaxSessionMinutes != 30 {
		t.Errorf("conditions did not reach the caller: %+v", d)
	}
}

// A refusal nobody can act on is barely better than no message at all.
func TestRefusalsExplainThemselves(t *testing.T) {
	p := policy("business-hours", store.PolicyScopeTenant)
	p.TimeWindows = []store.TimeWindow{{
		Days: []int{1, 2, 3, 4, 5}, StartMinute: 9 * 60, EndMinute: 18 * 60, Timezone: "Asia/Kolkata",
	}}

	req := request()
	req.Now = time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC) // a Sunday

	d := Evaluate(machine(), []*store.RemoteAccessPolicy{p}, req)
	if d.Allowed {
		t.Fatal("Sunday was permitted")
	}
	for _, want := range []string{"business-hours", "Mon", "09:00", "18:00", "Asia/Kolkata"} {
		if !strings.Contains(d.Reason, want) {
			t.Errorf("refusal %q does not mention %q", d.Reason, want)
		}
	}
}
