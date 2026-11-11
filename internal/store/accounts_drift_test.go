package store

import (
	"strings"
	"testing"
)

// The account inventory is the evidence least-privilege policy is written
// against. A mismatch here is not a compile error on either side: the reports
// simply stop arriving, and the portal shows a fleet where nobody holds local
// administrator rights — which is indistinguishable from a fleet that is
// already locked down, and is the most dangerous thing this product could
// display incorrectly.

func TestPrivInventoryDiscriminatorMatchesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/privinventory/report.go")

	const want = `ReportDiscriminator = "__priv_inventory__"`
	if !strings.Contains(src, want) {
		t.Fatalf("the agent no longer defines %s — account snapshots would never arrive", want)
	}
}

func TestPrivScanCommandIDMatchesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/privinventory/report.go")

	const want = `PrivScanCommandID = "__vsay_priv_scan__"`
	if !strings.Contains(src, want) {
		t.Fatalf("the agent no longer defines %s — \"scan now\" would be ignored", want)
	}
}

// The agent must still route the scan command.
//
// Worth its own check because of how the agent handles an unrecognised
// command id: it falls through to shell execution. A command this backend
// still sends but the agent no longer matches does not become a no-op — it
// becomes a string handed to the executor.
func TestAgentStillRoutesThePrivScanCommand(t *testing.T) {
	src := readAgentFile(t, "internal/agent/agent.go")

	if !strings.Contains(src, "cmd.CommandId == privinventory.PrivScanCommandID") {
		t.Error("the agent no longer routes the account-scan command — it would " +
			"fall through to shell execution instead of being ignored")
	}
}

// Every key the backend decodes must exist as a json tag on the agent's own
// type. A renamed field decodes to its zero value rather than failing, and the
// two that matter fail silently in opposite, equally wrong directions:
// is_admin arriving false shows a compliant fleet, is_local arriving false
// makes every account look like a directory account policy may not touch.
func TestAccountFieldsExistOnTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/privinventory/privinventory.go")

	for _, tag := range []string{
		`json:"id"`, `json:"username"`, `json:"full_name,omitempty"`,
		`json:"uid,omitempty"`, `json:"sid,omitempty"`,
		`json:"is_admin"`, `json:"is_local"`, `json:"source"`,
		`json:"shell,omitempty"`, `json:"home_dir,omitempty"`,
		`json:"disabled,omitempty"`, `json:"hidden,omitempty"`,
		`json:"last_login,omitempty"`,
	} {
		if !strings.Contains(src, tag) {
			t.Errorf("the agent's Account no longer carries %s — that field would arrive empty", tag)
		}
	}
}

// is_admin and is_local must NOT be omitempty.
//
// On a bool, omitempty drops the field when it is false — so an account that
// is not an administrator would arrive with the key absent. That decodes the
// same as false here and is harmless today, but it makes the two states
// indistinguishable on the wire, and any future reader that needs to tell
// "reported as false" from "not reported" would have no way to.
func TestTheDecisiveBooleansAreAlwaysOnTheWire(t *testing.T) {
	src := readAgentFile(t, "internal/privinventory/privinventory.go")

	for _, bad := range []string{`json:"is_admin,omitempty"`, `json:"is_local,omitempty"`} {
		if strings.Contains(src, bad) {
			t.Errorf("the agent carries %s — false would be dropped from the payload entirely", bad)
		}
	}
}

func TestPrivSnapshotEnvelopeMatchesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/privinventory/privinventory.go")

	for _, tag := range []string{
		`json:"collected_at"`, `json:"os"`, `json:"accounts"`,
		`json:"admin_group,omitempty"`,
	} {
		if !strings.Contains(src, tag) {
			t.Errorf("the agent's Snapshot no longer carries %s", tag)
		}
	}

	report := readAgentFile(t, "internal/privinventory/report.go")
	if !strings.Contains(report, `json:"agent_version"`) {
		t.Error("the agent's Report no longer carries json:\"agent_version\"")
	}
}

// The agent's own eligibility rule and the backend's copy of it must agree
// about the boundary. They are separate implementations on purpose — the
// backend needs an answer for machines that are offline — but a boundary that
// drifts means the simulation counts one set of accounts and the endpoint
// acts on another.
func TestTheSystemAccountBoundaryAgreesWithTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/privinventory/privinventory.go")

	if !strings.Contains(src, "systemUIDCeiling = 500") {
		t.Error("the agent's system-UID ceiling is no longer 500 — the backend's " +
			"demotable() uses that boundary and would count a different set of accounts")
	}
	for _, rid := range []string{`"-500"`, `"-501"`} {
		if !strings.Contains(src, rid) {
			t.Errorf("the agent no longer exempts the Windows built-in RID %s", rid)
		}
	}
}

// ── Least-privilege policy and enforcement ──────────────────────────────────

// The policy that decides who holds administrator rights. A drifted id here
// does not merely stop working: the agent falls through to SHELL EXECUTION
// for a command id it does not recognise, so the policy document would be
// handed to the executor.
func TestPrivPolicyCommandIDMatchesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/agent/privpolicy.go")

	const want = `PrivPolicyCommandID = "__vsay_privpolicy__"`
	if !strings.Contains(src, want) {
		t.Fatalf("the agent no longer defines %s — pushed privilege policies would be ignored", want)
	}
}

func TestAgentStillRoutesThePrivPolicyCommand(t *testing.T) {
	src := readAgentFile(t, "internal/agent/agent.go")

	if !strings.Contains(src, "cmd.CommandId == PrivPolicyCommandID") {
		t.Error("the agent no longer routes the privilege policy command — the policy " +
			"document would fall through to shell execution")
	}
}

func TestPrivEnforcementDiscriminatorMatchesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/agent/privpolicy.go")

	const want = `PrivEventDiscriminator = "__priv_enforcement__"`
	if !strings.Contains(src, want) {
		t.Fatalf("the agent no longer defines %s — what the endpoint did about "+
			"administrator rights would never be recorded", want)
	}
}

// Every key the backend decodes must exist as a json tag on the agent's type.
func TestPrivEventFieldsExistOnTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/privcontrol/privcontrol.go")

	for _, tag := range []string{
		`json:"at"`, `json:"mechanism"`, `json:"outcome"`,
		`json:"username,omitempty"`, `json:"reason,omitempty"`, `json:"detail,omitempty"`,
	} {
		if !strings.Contains(src, tag) {
			t.Errorf("the agent's Event no longer carries %s", tag)
		}
	}
}

// The policy the backend sends and the struct the agent decodes it into.
//
// demote_admins is the instruction itself. Its zero value is false, so a
// drift there fails safe — but keep_admin's zero value is EMPTY, and a drift
// there would enforce with no exemptions at all, demoting exactly the people
// the policy was written to protect.
func TestPrivilegePolicyFieldsExistOnTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/privpolicy/privpolicy.go")

	for _, tag := range []string{
		`json:"mode"`, `json:"demote_admins"`, `json:"keep_admin,omitempty"`,
		`json:"break_glass"`, `json:"elevation"`,
		`json:"allow_install_requests"`, `json:"allow_admin_requests"`,
		`json:"max_grant_minutes,omitempty"`, `json:"sudo_commands,omitempty"`,
		`json:"path"`, `json:"any_arguments,omitempty"`,
	} {
		if !strings.Contains(src, tag) {
			t.Errorf("the agent's privilege policy no longer carries %s", tag)
		}
	}
}

// demote_admins must NOT be omitempty.
//
// On a bool, omitempty drops the field when it is false. That is harmless in
// this direction today, but it makes "told not to demote" and "not told"
// indistinguishable on the wire — and those two are exactly the states this
// product must never confuse.
func TestTheDemotionInstructionIsAlwaysOnTheWire(t *testing.T) {
	src := readAgentFile(t, "internal/privpolicy/privpolicy.go")

	if strings.Contains(src, `json:"demote_admins,omitempty"`) {
		t.Error("the agent carries demote_admins as omitempty — false would be dropped entirely")
	}
}

// The mechanism names are a shared vocabulary: the backend maps them to audit
// actions and the portal labels rows with them. A rename on the agent would
// produce a category nothing counts.
func TestPrivMechanismNamesMatchTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/privcontrol/privcontrol.go")

	for _, name := range []string{
		`"admin-demoted"`, `"admin-restored"`, `"admin-refused"`,
		`"admin-deferred"`, `"break-glass-created"`, `"sudo-rules"`,
	} {
		if !strings.Contains(src, name) {
			t.Errorf("the agent no longer reports the mechanism %s", name)
		}
	}
}

// The blast-radius breaker must exist and must be a real limit. Removed, or
// raised to something meaningless, it would stop being the thing that makes a
// fleet-wide mistake survivable.
func TestTheAgentStillLimitsHowManyAccountsOnePassCanDemote(t *testing.T) {
	src := readAgentFile(t, "internal/privpolicy/privpolicy.go")

	if !strings.Contains(src, "MaxDemotedPerPass = ") {
		t.Fatal("the agent no longer bounds how many accounts one pass may demote")
	}
}

// The invariant that makes this feature survivable at all.
func TestTheAgentStillRefusesToLeaveAMachineWithoutAnAdministrator(t *testing.T) {
	src := readAgentFile(t, "internal/privpolicy/privpolicy.go")

	if !strings.Contains(src, "RefusedNoAdminLeft") {
		t.Fatal("the agent no longer refuses to leave a machine with no administrator")
	}
}

// Uninstalling must give the rights back. Without this the estate is left
// permanently damaged by the product's own removal.
func TestUninstallStillRestoresAdministratorRights(t *testing.T) {
	src := readAgentFile(t, "cmd/agent/uninstall.go")

	if !strings.Contains(src, "releaseAdminRights()") {
		t.Fatal("the agent's uninstall no longer restores administrator rights")
	}
}

// The just-in-time admin grant. This is the field that finally gives the
// approval workflow an effect on the endpoint, so a drift here returns the
// product to the state this work existed to fix: the portal says granted and
// the machine changes nothing.
func TestAdminGrantFieldsExistOnTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/privpolicy/privpolicy.go")

	for _, tag := range []string{
		`json:"grants,omitempty"`, `json:"username"`, `json:"until"`,
	} {
		if !strings.Contains(src, tag) {
			t.Errorf("the agent's grant no longer carries %s", tag)
		}
	}
}

// The endpoint must check the grant's clock itself.
//
// A machine that has been offline for a week is still holding the last policy
// it was given. If only the server enforced expiry, that machine would go on
// honouring a lapsed grant for as long as it stayed offline.
func TestTheAgentChecksGrantExpiryItself(t *testing.T) {
	src := readAgentFile(t, "internal/privpolicy/privpolicy.go")

	if !strings.Contains(src, "func (e Effective) GrantedTo(") {
		t.Fatal("the agent no longer evaluates grant expiry on the endpoint")
	}
}

// ── Command elevation (the Windows sudo equivalent) ─────────────────────────

func TestElevateResultDiscriminatorMatchesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/agent/elevate.go")

	const want = `ElevateEventDiscriminator = "__elevate_result__"`
	if !strings.Contains(src, want) {
		t.Fatalf("the agent no longer defines %s — commands run with elevated rights "+
			"would never reach the audit trail", want)
	}
}

func TestElevateResultFieldsExistOnTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/elevate/elevate.go")

	for _, tag := range []string{
		`json:"id"`, `json:"user"`, `json:"command"`, `json:"allowed"`,
		`json:"verdict"`, `json:"exit_code"`, `json:"output,omitempty"`,
	} {
		if !strings.Contains(src, tag) {
			t.Errorf("the agent's elevation result no longer carries %s", tag)
		}
	}
}

// The identity a brokered command is decided on must come from the owner of
// the request file, never from the request body.
//
// This is the property the whole broker rests on: the queue directory is
// writable by people who are deliberately not administrators, so a body
// claiming "I am priya" is worth nothing. If this check ever fails, any
// standard user on the machine can run anything any other user is permitted
// to run.
func TestTheBrokerStillDecidesOnTheFileOwner(t *testing.T) {
	src := readAgentFile(t, "internal/elevate/elevate.go")

	if !strings.Contains(src, "req.User = verifiedUser") {
		t.Fatal("the broker no longer overwrites the request's claimed user with the " +
			"verified owner — a forged request body would be trusted")
	}

	queue := readAgentFile(t, "internal/elevate/queue.go")
	if !strings.Contains(queue, "ownerOf") {
		t.Fatal("the request queue no longer establishes the file's owner")
	}
}

// Both platforms must decide with the same function, or a command allowed on
// a Mac in a group is refused on a Windows machine in that group with nothing
// in the portal to explain it.
func TestWindowsAndUnixDecideWithTheSameFunction(t *testing.T) {
	broker := readAgentFile(t, "internal/elevate/elevate.go")

	if !strings.Contains(broker, "sudopolicy.Decide(") {
		t.Error("the Windows broker no longer uses sudopolicy.Decide — the two platforms " +
			"would drift about what a policy permits")
	}
}

// The self-check is how a Windows machine proves this works, since no Windows
// machine was available when it was written.
func TestTheSelfCheckCommandStillExists(t *testing.T) {
	src := readAgentFile(t, "cmd/agent/privilegeselfcheck.go")

	if !strings.Contains(src, `Use:   "privilege-selfcheck"`) {
		t.Fatal("the privilege self-check command is gone — there would be no way to " +
			"verify the enforcement path on a machine")
	}
	// The live test must put the account back even when the check fails.
	if !strings.Contains(src, "defer func() {") || !strings.Contains(src, "restored") {
		t.Error("the live write test no longer restores the account unconditionally — " +
			"a failed diagnostic could leave somebody demoted")
	}
}

// ── Creating an account from the portal ─────────────────────────────────────

func TestCreateAccountCommandIDMatchesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/agent/privpolicy.go")

	const want = `CreateAccountCommandID = "__vsay_createaccount__"`
	if !strings.Contains(src, want) {
		t.Fatalf("the agent no longer defines %s", want)
	}
}

// This command's payload carries a PASSWORD, and the agent's fallback path
// logs cmd.Command verbatim before handing it to the executor. If the routing
// is removed, every account creation writes an endpoint password into a log
// file that this product then ships to S3.
func TestTheAgentRoutesCreateAccountBeforeTheLoggingFallback(t *testing.T) {
	src := readAgentFile(t, "internal/agent/agent.go")

	routed := strings.Index(src, "cmd.CommandId == CreateAccountCommandID")
	if routed < 0 {
		t.Fatal("the agent no longer routes the create-account command — the payload, " +
			"which carries a password, would be logged and then shell-executed")
	}
	logged := strings.Index(src, `zap.String("command", cmd.Command)`)
	if logged >= 0 && routed > logged {
		t.Error("the create-account command is routed AFTER the generic command logging — " +
			"the password would reach the log first")
	}
}

func TestAccountSpecFieldsMatchTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/privcontrol/privcontrol.go")

	for _, tag := range []string{
		`json:"username"`, `json:"full_name,omitempty"`, `json:"password"`,
		`json:"admin,omitempty"`, `json:"hidden,omitempty"`,
		`json:"requested_by,omitempty"`,
	} {
		if !strings.Contains(src, tag) {
			t.Errorf("the agent's AccountSpec no longer carries %s", tag)
		}
	}
}

// The password must never reach a log. The agent's own logs are shipped to S3
// by this product, read by support, and kept for as long as retention says.
func TestTheAgentCanStillRedactTheAccountPassword(t *testing.T) {
	src := readAgentFile(t, "internal/privcontrol/privcontrol.go")

	if !strings.Contains(src, "func (s AccountSpec) Redacted()") {
		t.Fatal("the agent no longer has a way to log an account spec without its password")
	}
}

// An account asked for as a standard user that comes out an administrator is
// a silent hole in least privilege, and matters as much as one that failed.
func TestTheEndpointVerifiesTheAccountKindBothWays(t *testing.T) {
	for _, file := range []string{
		"internal/privcontrol/platform_darwin.go",
		"internal/privcontrol/platform_windows.go",
	} {
		src := readAgentFile(t, file)
		if !strings.Contains(src, "which was not asked for") {
			t.Errorf("%s no longer checks that a standard account did not come out "+
				"as an administrator", file)
		}
	}
}

// ── Managing an existing account ────────────────────────────────────────────

func TestAccountActionCommandIDMatchesTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/agent/privpolicy.go")

	const want = `AccountActionCommandID = "__vsay_accountaction__"`
	if !strings.Contains(src, want) {
		t.Fatalf("the agent no longer defines %s", want)
	}
}

func TestAgentStillRoutesTheAccountActionCommand(t *testing.T) {
	src := readAgentFile(t, "internal/agent/agent.go")

	if !strings.Contains(src, "cmd.CommandId == AccountActionCommandID") {
		t.Error("the agent no longer routes account actions — they would fall through " +
			"to shell execution instead of being ignored")
	}
}

func TestAccountActionFieldsMatchTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/privcontrol/privcontrol.go")

	for _, tag := range []string{
		`json:"action"`, `json:"username"`, `json:"value"`,
		`json:"until,omitempty"`, `json:"requested_by,omitempty"`,
	} {
		if !strings.Contains(src, tag) {
			t.Errorf("the agent's AccountAction no longer carries %s", tag)
		}
	}
}

// The action names are a shared vocabulary. A rename on either side turns
// every click in the portal into "unknown account action" on the endpoint.
func TestTheAccountActionNamesMatchTheAgent(t *testing.T) {
	src := readAgentFile(t, "internal/privcontrol/privcontrol.go")

	for _, name := range []string{`ActionSetAdmin   = "set-admin"`, `ActionSetEnabled = "set-enabled"`} {
		if !strings.Contains(src, name) {
			t.Errorf("the agent no longer defines %s", name)
		}
	}
}

// A time-limited grant has to end on the ENDPOINT's own clock.
//
// If expiry depended on the server pushing something, a machine that is
// asleep, offline or simply unreachable when the grant lapses would keep
// administrator rights indefinitely — which is the failure mode that makes
// "just-in-time access" a claim rather than a control.
func TestTheEndpointEndsItsOwnTimeLimitedGrants(t *testing.T) {
	src := readAgentFile(t, "internal/privcontrol/privcontrol.go")

	if !strings.Contains(src, "func (e *Enforcer) ExpireGrants(") {
		t.Fatal("the agent no longer expires its own grants — one would outlive its " +
			"end time on any machine that went offline")
	}

	loop := readAgentFile(t, "internal/agent/privpolicy.go")
	if !strings.Contains(loop, "grantExpiryLoop") {
		t.Fatal("nothing on the agent runs the grant expiry")
	}
	// It must not share the quarter-hourly policy ticker, or the short grants
	// the portal offers would overrun by up to fifteen minutes.
	if !strings.Contains(loop, "grantExpiryPoll = time.Minute") {
		t.Error("the grant expiry no longer runs on its own short cycle")
	}
}

// Grants must survive a restart, or an agent that restarts mid-grant never
// takes the rights back.
func TestGrantsArePersistedOnTheEndpoint(t *testing.T) {
	src := readAgentFile(t, "internal/privcontrol/privcontrol.go")

	if !strings.Contains(src, `Promoted map[string]time.Time `) {
		t.Error("the agent no longer persists which accounts it promoted — a restart " +
			"mid-grant would leave standing administrator rights behind")
	}
}

// When a grant ends has to reach the portal, or it shows somebody as an
// administrator with no sign that the rights are temporary.
func TestTheGrantExpiryIsReportedWithTheInventory(t *testing.T) {
	src := readAgentFile(t, "internal/privinventory/privinventory.go")

	if !strings.Contains(src, `json:"admin_until,omitempty"`) {
		t.Error("the agent's Account no longer carries admin_until — the portal would " +
			"show a temporary grant as though it were permanent")
	}

	report := readAgentFile(t, "internal/agent/privinventory.go")
	if !strings.Contains(report, "mergeGrantExpiry") {
		t.Fatal("nothing fills in admin_until — it would always arrive empty")
	}
}
