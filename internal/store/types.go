package store

import (
	"context"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User data comes from vsay-auth service via headers (X-Username, X-User-ID, X-User-Email, etc.)
// No local user collection in backend

type Machine struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	AgentID           string             `bson:"agent_id" json:"agent_id"`                     // Set after agent connects
	RegistrationToken string             `bson:"registration_token" json:"registration_token"` // Unique token for registration
	Name              string             `bson:"name" json:"name"`
	Description       string             `bson:"description" json:"description"`
	OS                string             `bson:"os" json:"os"`
	IPAddress         string             `bson:"ip_address" json:"ip_address"`
	Status            string             `bson:"status" json:"status"` // "online", "offline", "pending", "revoked"
	LastActive        time.Time          `bson:"last_active" json:"last_active"`
	Uptime            int64              `bson:"uptime" json:"uptime"` // seconds
	OwnerID           primitive.ObjectID `bson:"owner_id" json:"owner_id"`
	TenantID          string             `bson:"tenant_id" json:"tenant_id"`
	OrgID             string             `bson:"org_id" json:"org_id"`
	GroupIDs          []string           `bson:"group_ids" json:"group_ids"`         // Group IDs this machine belongs to
	AllowedUsers      []string           `bson:"allowed_users" json:"allowed_users"` // List of usernames allowed to access
	ResourceStats     ResourceStats      `bson:"resource_stats" json:"resource_stats"`
	Metadata          map[string]string  `bson:"metadata" json:"metadata"`
	DeployApplication bool               `bson:"deploy_application" json:"deploy_application"`
	CustomScript      string             `bson:"custom_script,omitempty" json:"custom_script,omitempty"`

	// Security fields
	Revoked         bool       `bson:"revoked" json:"revoked"` // True = all cert signing rejected + gRPC kicked
	RevokedAt       *time.Time `bson:"revoked_at,omitempty" json:"revoked_at,omitempty"`
	CertFingerprint string     `bson:"cert_fingerprint,omitempty" json:"cert_fingerprint,omitempty"` // SHA-256 of last issued client cert

	// NotifyEmails are alerted when an external (non-vsay) SSH/RDP login is detected on
	// the machine. Collected opportunistically from authorized users who view the machine.
	NotifyEmails []string `bson:"notify_emails,omitempty" json:"notify_emails,omitempty"`

	// AgentStats is the vsay agent PROCESS's own resource usage (latest report), for
	// the portal's Agent Monitoring section. Distinct from ResourceStats (the whole machine).
	AgentStats *AgentStats `bson:"agent_stats,omitempty" json:"agent_stats,omitempty"`

	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

// AgentStats is the vsay agent process's own resource usage.
type AgentStats struct {
	CPUPercent   float64   `bson:"cpu_percent" json:"cpu_percent"`
	MemoryMB     float64   `bson:"memory_mb" json:"memory_mb"`
	Goroutines   int       `bson:"goroutines" json:"goroutines"`
	UptimeSec    int64     `bson:"uptime_sec" json:"uptime_sec"`
	Version      string    `bson:"version" json:"version"`
	OpenTunnels  int       `bson:"open_tunnels" json:"open_tunnels"`   // forwarded RDP/VNC connections
	OpenSessions int       `bson:"open_sessions" json:"open_sessions"` // active terminal (PTY) sessions
	UpdatedAt    time.Time `bson:"updated_at" json:"updated_at"`
}

// AccessEvent records an EXTERNAL login to the machine (SSH on Linux, RDP/console on
// Windows) — i.e. someone connecting directly, bypassing the vsay portal. The agent
// detects these and reports login/logout so we can alert users and show a history.
type AccessEvent struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	MachineID   primitive.ObjectID `bson:"machine_id" json:"machine_id"`
	AgentID     string             `bson:"agent_id" json:"agent_id"`
	MachineName string             `bson:"machine_name" json:"machine_name"`
	TenantID    string             `bson:"tenant_id" json:"tenant_id"`
	Protocol    string             `bson:"protocol" json:"protocol"` // "ssh" | "rdp" | "console"
	OSUser      string             `bson:"os_user" json:"os_user"`   // the OS account that logged in
	SourceIP    string             `bson:"source_ip" json:"source_ip"`
	Line        string             `bson:"line" json:"line"`     // tty/session id (dedup key with os_user)
	Active      bool               `bson:"active" json:"active"` // still logged in
	LoginAt     time.Time          `bson:"login_at" json:"login_at"`
	LogoutAt    *time.Time         `bson:"logout_at,omitempty" json:"logout_at,omitempty"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

// AccessEventKey identifies one login session. The pair is what the agent uses
// to deduplicate, so the backend matches on exactly the same thing.
type AccessEventKey struct {
	OSUser string
	Line   string
}

// InstalledApp is one application on one machine, as last reported by its
// agent.
//
// Rows are marked gone rather than deleted, because "what was uninstalled last
// week" is a question this product exists to answer and a delete destroys it.
type InstalledApp struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	MachineID   primitive.ObjectID `bson:"machine_id" json:"machine_id"`
	AgentID     string             `bson:"agent_id" json:"agent_id"`
	MachineName string             `bson:"machine_name" json:"machine_name"`
	TenantID    string             `bson:"tenant_id" json:"tenant_id"`

	// AppKey is the application's identity on this machine, assigned by the
	// agent. It never contains the version: if it did, every Chrome
	// auto-update would look like an uninstall followed by an install, and
	// FirstSeen would reset every week.
	AppKey string `bson:"app_key" json:"app_key"`

	Name      string `bson:"name" json:"name"`
	NameLower string `bson:"name_lower" json:"-"`
	Version   string `bson:"version,omitempty" json:"version,omitempty"`

	Publisher      string `bson:"publisher,omitempty" json:"publisher,omitempty"`
	PublisherLower string `bson:"publisher_lower,omitempty" json:"-"`

	InstallPath string `bson:"install_path,omitempty" json:"install_path,omitempty"`
	ExePath     string `bson:"exe_path,omitempty" json:"exe_path,omitempty"`
	BundleID    string `bson:"bundle_id,omitempty" json:"bundle_id,omitempty"`

	Source string `bson:"source" json:"source"`
	Scope  string `bson:"scope,omitempty" json:"scope,omitempty"`
	OSUser string `bson:"os_user,omitempty" json:"os_user,omitempty"`
	Arch   string `bson:"arch,omitempty" json:"arch,omitempty"`

	InstalledAt *time.Time `bson:"installed_at,omitempty" json:"installed_at,omitempty"`

	// Hash fields are owned by the on-demand hash path, never by a scan.
	// A scan upsert that touched them would wipe a computed hash every time
	// the machine reported.
	SHA256    string     `bson:"sha256,omitempty" json:"sha256,omitempty"`
	HashState string     `bson:"hash_state,omitempty" json:"hash_state,omitempty"`
	HashedAt  *time.Time `bson:"hashed_at,omitempty" json:"hashed_at,omitempty"`

	FirstSeen time.Time  `bson:"first_seen" json:"first_seen"`
	LastSeen  time.Time  `bson:"last_seen" json:"last_seen"`
	Present   bool       `bson:"present" json:"present"`
	RemovedAt *time.Time `bson:"removed_at,omitempty" json:"removed_at,omitempty"`

	// ScanID is the snapshot that last touched this row. The removal sweep
	// works by marking everything the latest scan did NOT touch, which is far
	// cheaper than asking the database about three hundred keys individually.
	ScanID    string    `bson:"scan_id" json:"-"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

// InventoryScan records one reported snapshot.
//
// Without it, "this machine has no software" and "this machine has never
// reported" look identical, which is the most common support question any
// inventory product gets.
type InventoryScan struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	MachineID primitive.ObjectID `bson:"machine_id" json:"machine_id"`
	AgentID   string             `bson:"agent_id" json:"agent_id"`
	TenantID  string             `bson:"tenant_id" json:"tenant_id"`
	ScanID    string             `bson:"scan_id" json:"scan_id"`

	OS           string `bson:"os,omitempty" json:"os,omitempty"`
	AgentVersion string `bson:"agent_version,omitempty" json:"agent_version,omitempty"`

	Reported int   `bson:"reported" json:"reported"`
	Added    int64 `bson:"added" json:"added"`
	Updated  int64 `bson:"updated" json:"updated"`
	Removed  int64 `bson:"removed" json:"removed"`
	Chunks   int   `bson:"chunks" json:"chunks"`

	// CollectError is whatever the agent's collector reported. A scan carrying
	// one is never allowed to mark software as removed.
	CollectError string `bson:"collect_error,omitempty" json:"collect_error,omitempty"`

	// Complete is false until the final chunk arrives. An incomplete scan is a
	// partial picture, not a statement that the rest is gone.
	Complete bool `bson:"complete" json:"complete"`

	StartedAt  time.Time  `bson:"started_at" json:"started_at"`
	FinishedAt *time.Time `bson:"finished_at,omitempty" json:"finished_at,omitempty"`
}

// InventoryQuery filters a per-machine application listing.
//
// A struct rather than the codebase's usual positional (limit, skip) pair,
// because this needs search and include-removed as well and five positional
// arguments is how call sites start passing them in the wrong order.
type InventoryQuery struct {
	Search         string
	Source         string
	IncludeRemoved bool
	Limit, Skip    int
}

// CatalogEntry is one distinct application across the fleet.
type CatalogEntry struct {
	Name         string   `bson:"name" json:"name"`
	Publisher    string   `bson:"publisher" json:"publisher"`
	MachineCount int      `bson:"machine_count" json:"machine_count"`
	InstallCount int      `bson:"install_count" json:"install_count"`
	VersionCount int      `bson:"version_count" json:"version_count"`
	Versions     []string `bson:"versions" json:"versions"`
	SampleExe    string   `bson:"sample_exe,omitempty" json:"sample_exe,omitempty"`
	SampleBundle string   `bson:"sample_bundle,omitempty" json:"sample_bundle,omitempty"`
}

// CatalogQuery filters the fleet-wide catalog.
type CatalogQuery struct {
	Search      string
	Limit, Skip int
}

// InventoryCoverage reports how much of the fleet the inventory actually
// covers.
//
// Every number derived from the inventory — a catalog count, a policy
// simulation — is only as honest as this. "47 apps would be blocked" means
// nothing without "and 17 of your 100 machines have never reported".
type InventoryCoverage struct {
	MachinesTotal    int       `json:"machines_total"`
	MachinesReported int       `json:"machines_reported"`
	MachinesStale    int       `json:"machines_stale"`
	OldestReportAt   time.Time `json:"oldest_report_at,omitempty"`
}

// Application-control policy.
//
// A policy is authored, simulated against the fleet's real inventory, and then
// enforced — or not. Whether any of it acts on an endpoint is one switch per
// tenant, AppControlSettings.Enforcement, and not a property of the policy
// itself: that way "what would this do" and "do it" stay separate decisions.

// Policy actions.
const (
	ActionAllow   = "allow"
	ActionBlock   = "block"
	ActionElevate = "elevate"
	// ActionDefault stops evaluation and falls through to the policy's
	// DefaultAction — the explicit carve-out an operator needs to say "this
	// one is none of the above".
	ActionDefault = "default"
)

// Policy modes.
const (
	// ModeAudit records what would have happened and changes nothing.
	ModeAudit = "audit"
	// ModeEnforce acts on the decision. Only reached when the tenant's
	// AppControlSettings.Enforcement is on.
	ModeEnforce = "enforce"
)

// Policy scopes, least specific first. Named with the Policy prefix because
// InstalledApp.Scope already means something different — whether an install is
// machine-wide or for one account — and two unrelated meanings of "machine
// scope" in one package is how the wrong constant gets used.
const (
	PolicyScopeTenant  = "tenant"
	PolicyScopeGroup   = "group"
	PolicyScopeMachine = "machine"
)

// Install scopes, as reported by the agent for each application.
const (
	InstallScopeMachine = "machine"
	InstallScopeUser    = "user"
)

// Match operators.
const (
	OpEquals   = "equals"
	OpContains = "contains"
	OpPrefix   = "prefix"
	OpSuffix   = "suffix"
	OpWildcard = "wildcard"
)

// AppControlSettings is a tenant's application-control configuration.
//
// Today it holds one thing, and that one thing is the switch between a product
// that watches and a product that acts on somebody's laptop. It is a stored
// per-tenant setting rather than a build-time constant because turning
// enforcement on is a decision an organisation makes for itself, after reading
// a simulation, and should not require a deployment.
type AppControlSettings struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	TenantID string             `bson:"tenant_id" json:"tenant_id"`

	// Enforcement is the master switch. While it is false every policy
	// resolves to audit mode however its own Mode is set, so no endpoint acts
	// on anything. The default — for a tenant that has never chosen, and for a
	// settings document that fails to read — is false.
	Enforcement bool `bson:"enforcement" json:"enforcement"`

	UpdatedAt time.Time `bson:"updated_at,omitempty" json:"updated_at,omitempty"`
	UpdatedBy string    `bson:"updated_by,omitempty" json:"updated_by,omitempty"`
}

// Enforcement mechanisms, as reported by an agent.
const (
	// EnforceTerminate: a running program was closed.
	EnforceTerminate = "terminate"
	// EnforceLock: an application was prevented from launching.
	EnforceLock = "launch-lock"
	// EnforceUnlock: an application that is no longer blocked was restored.
	EnforceUnlock = "launch-unlock"
	// EnforceRefused: the agent declined to apply a policy, because doing so
	// would have blocked an implausible number of applications at once.
	EnforceRefused = "refused"
	// EnforceQuarantine: the application was moved off the machine, into a
	// directory only the agent writes to. A move, never a delete.
	EnforceQuarantine = "quarantine"
	// EnforceRestore: a quarantined application was put back where it was.
	EnforceRestore = "restore"
	// EnforceElevate: an application was granted the right to run with
	// administrator rights. The only mechanism here that GIVES privilege
	// rather than taking it away, which is why it is counted separately and
	// reported separately.
	EnforceElevate = "elevate"
	// EnforceElevateRevoked: that grant was withdrawn.
	EnforceElevateRevoked = "elevate-revoked"
	// The outcome of one enforcement action, as the agent reports it.
	//
	// These were previously compared as bare strings wherever the backend
	// needed them, with the only definition living in the agent. The agent
	// renaming one would not break a build here — it would quietly stop
	// matching, and whatever the backend does for a failure would simply stop
	// happening. Pinned against the agent's source by the drift test.

	// OutcomeApplied: the agent did the thing.
	OutcomeApplied = "applied"
	// OutcomeFailed: the agent tried and could not. For elevation this is the
	// normal outcome today, because no platform implements it.
	OutcomeFailed = "failed"
	// OutcomeSkipped: the agent deliberately did nothing, for example in audit
	// mode or where a safety rule refused.
	OutcomeSkipped = "skipped"

	// EnforceElevateLaunch: an application actually RAN elevated. The others
	// describe configuration; this one describes something that happened, and
	// it is the line an auditor asks for.
	EnforceElevateLaunch = "elevate-launch"
)

// EnforcementEvent is one thing an agent did, or declined to do, to the
// software on a machine.
//
// This is the answer to "why did my application stop working", and it is the
// only answer there is: the decision was made on the endpoint, in a process
// nobody was watching, possibly while the machine was offline. Machine and
// tenant are denormalised onto every row so that reading a fleet-wide history
// never needs a join.
// EnforcementCount identifies one bucket of enforcement activity.
//
// Mechanism alone is not an answer. "elevate" counts an endpoint being ASKED
// to elevate; whether it did is the outcome, and the two were conflated in the
// compliance report until this type existed — reporting every refusal as a
// privilege granted.
type EnforcementCount struct {
	Mechanism string `bson:"mechanism"`
	Outcome   string `bson:"outcome"`
}

// Applied totals one mechanism's successes, which is what a report means when
// it says something was done.
func Applied(counts map[EnforcementCount]int64, mechanisms ...string) int64 {
	var n int64
	for _, mech := range mechanisms {
		n += counts[EnforcementCount{Mechanism: mech, Outcome: OutcomeApplied}]
	}
	return n
}

// NotApplied totals the times a mechanism was asked for and did not happen —
// the figure that says a policy is not being honoured.
func NotApplied(counts map[EnforcementCount]int64, mechanisms ...string) int64 {
	var n int64
	for key, c := range counts {
		for _, mech := range mechanisms {
			if key.Mechanism == mech && key.Outcome != OutcomeApplied {
				n += c
			}
		}
	}
	return n
}

// EnforcementEventQuery narrows a listing of enforcement activity.
//
// A struct rather than six positional arguments, three of which are strings:
// GetEnforcementEvents(tenant, agent, search, …) is a call where transposing
// two of them compiles, runs, and quietly returns the wrong tenant's history.
type EnforcementEventQuery struct {
	TenantID string
	// AgentID narrows to one machine; empty means the whole fleet.
	AgentID string

	// Search is matched against the application, where it lives, and the rule
	// or policy that decided — the four things somebody has in hand when they
	// ask why their software stopped. It is LITERAL text: whatever is typed is
	// escaped before it reaches the database, so a path containing "." or
	// "C:\Program Files (x86)" searches for itself rather than being read as
	// a pattern that matches everything or fails outright.
	Search string

	Limit int
	Skip  int
}

type EnforcementEvent struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	TenantID string             `bson:"tenant_id" json:"tenant_id"`
	AgentID  string             `bson:"agent_id" json:"agent_id"`

	MachineID   primitive.ObjectID `bson:"machine_id,omitempty" json:"machine_id,omitempty"`
	MachineName string             `bson:"machine_name,omitempty" json:"machine_name,omitempty"`

	// At is when it happened on the endpoint; CreatedAt is when it reached
	// here. They differ by however long the machine was offline, and the gap
	// is itself worth seeing.
	At        time.Time `bson:"at" json:"at"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`

	Mechanism string `bson:"mechanism" json:"mechanism"`
	Outcome   string `bson:"outcome" json:"outcome"`

	AppName  string `bson:"app_name,omitempty" json:"app_name,omitempty"`
	Path     string `bson:"path,omitempty" json:"path,omitempty"`
	BundleID string `bson:"bundle_id,omitempty" json:"bundle_id,omitempty"`

	// Rule and Policy name what decided. Both empty means the policy default
	// applied rather than any rule, which is a different conversation to have
	// with the person whose software stopped.
	Rule   string `bson:"rule,omitempty" json:"rule,omitempty"`
	Policy string `bson:"policy,omitempty" json:"policy,omitempty"`

	PID int `bson:"pid,omitempty" json:"pid,omitempty"`

	// Detail carries the reason for a failure or a refusal.
	Detail string `bson:"detail,omitempty" json:"detail,omitempty"`

	// How the endpoint prevents launches, which differs by platform and is
	// what an operator needs in order to know how strong the block is.
	EnforcedBy string `bson:"enforced_by,omitempty" json:"enforced_by,omitempty"`
}

// AppPolicy is one named set of ordered rules applying to some machines.
//
// One document per policy with an ordered rule list, rather than a document
// per rule: policies are authored, reviewed and audited as a unit, and
// first-match-wins is only explainable if the rules are a numbered list an
// operator can read top to bottom.
type AppPolicy struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	TenantID    string             `bson:"tenant_id" json:"tenant_id"`
	Name        string             `bson:"name" json:"name"`
	Description string             `bson:"description,omitempty" json:"description,omitempty"`
	Enabled     bool               `bson:"enabled" json:"enabled"`

	Scope PolicyScope `bson:"scope" json:"scope"`

	// Mode is audit or enforce. A policy asking to enforce only does so once
	// the tenant's enforcement switch is on: the resolver forces audit
	// otherwise, so a policy saved as enforce cannot act by itself.
	Mode string `bson:"mode" json:"mode"`

	// Priority breaks ties between policies at the same scope. Higher wins.
	Priority int `bson:"priority" json:"priority"`

	// DefaultAction applies when no rule matches.
	DefaultAction string `bson:"default_action" json:"default_action"`

	// RemoveBlocked makes a block bite harder: instead of only being stopped
	// from launching, matching software is MOVED off the machine into a
	// directory only the agent writes to.
	//
	// A move, never a delete, and the agent puts it back when the policy stops
	// blocking it or when the agent is uninstalled. That is what makes this
	// safe enough to offer at all — a rule aimed at the wrong application is
	// recoverable from a move and is not recoverable from a delete.
	//
	// It applies only to software a RULE matched. The policy's own catch-all
	// cannot reach it, because a default that swept an entire Applications
	// folder into quarantine is not something anybody means to express.
	RemoveBlocked bool `bson:"remove_blocked,omitempty" json:"remove_blocked,omitempty"`

	Rules []PolicyRule `bson:"rules" json:"rules"`

	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
	CreatedBy string    `bson:"created_by,omitempty" json:"created_by,omitempty"`
	UpdatedBy string    `bson:"updated_by,omitempty" json:"updated_by,omitempty"`
}

// PolicyScope says which machines a policy applies to.
type PolicyScope struct {
	Kind     string   `bson:"kind" json:"kind"`
	GroupIDs []string `bson:"group_ids,omitempty" json:"group_ids,omitempty"`
	// AgentIDs, not machine ObjectIDs — agent_id is the key the rest of the
	// fleet is addressed by.
	AgentIDs []string `bson:"agent_ids,omitempty" json:"agent_ids,omitempty"`
}

// PolicyRule is one ordered decision.
type PolicyRule struct {
	// ID is stable across reordering, so simulation results and audit entries
	// can cite a rule that is still recognisable after the list is edited.
	ID      string        `bson:"id" json:"id"`
	Name    string        `bson:"name" json:"name"`
	Enabled bool          `bson:"enabled" json:"enabled"`
	Action  string        `bson:"action" json:"action"`
	Match   MatchCriteria `bson:"match" json:"match"`
	Comment string        `bson:"comment,omitempty" json:"comment,omitempty"`
}

// MatchCriteria selects applications.
//
// Populated fields are ANDed; the values within one field are ORed. An
// entirely empty criteria matches NOTHING — never everything. That is the
// single most important rule here: a half-filled form must not silently become
// a fleet-wide block.
type MatchCriteria struct {
	AppName   StringMatch `bson:"app_name" json:"app_name"`
	Publisher StringMatch `bson:"publisher" json:"publisher"`
	FilePath  StringMatch `bson:"file_path" json:"file_path"`
	BundleID  StringMatch `bson:"bundle_id" json:"bundle_id"`
	// SHA256 is exact, lowercase hex. Hash rules pin one exact build and stop
	// matching the moment it is patched, which is why they are last.
	SHA256 []string `bson:"sha256,omitempty" json:"sha256,omitempty"`
}

// StringMatch is one field's comparison.
type StringMatch struct {
	Op     string   `bson:"op,omitempty" json:"op,omitempty"`
	Values []string `bson:"values,omitempty" json:"values,omitempty"`
	// CaseSensitive is off by default. Publishers and paths arrive from
	// registries and filesystems with inconsistent casing, and a rule that
	// misses because of it fails silently.
	CaseSensitive bool `bson:"case_sensitive,omitempty" json:"case_sensitive,omitempty"`
}

// Empty reports whether this field constrains anything.
func (m StringMatch) Empty() bool {
	for _, v := range m.Values {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return true
}

// Empty reports whether the criteria constrains anything at all.
func (c MatchCriteria) Empty() bool {
	return c.AppName.Empty() && c.Publisher.Empty() &&
		c.FilePath.Empty() && c.BundleID.Empty() && len(c.SHA256) == 0
}

// Remote-access policy.
//
// Who may connect to which machines, by what means, at what times, and under
// what conditions. It sits BEHIND the existing ownership and allowed-user
// checks, never in front of them: a policy can only narrow what somebody may
// already do, never widen it. That ordering is what stops a mistyped policy
// from handing a stranger a session.

// Remote access kinds, matching the three ways in.
const (
	AccessAttended   = "attended"   // remote control of the user's live session
	AccessUnattended = "unattended" // RDP/VNC, a separate desktop
	AccessTerminal   = "terminal"   // shell
)

// RemoteAccessPolicy is one named rule set.
type RemoteAccessPolicy struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	TenantID    string             `bson:"tenant_id" json:"tenant_id"`
	Name        string             `bson:"name" json:"name"`
	Description string             `bson:"description,omitempty" json:"description,omitempty"`
	Enabled     bool               `bson:"enabled" json:"enabled"`

	Scope    PolicyScope `bson:"scope" json:"scope"`
	Priority int         `bson:"priority" json:"priority"`

	// AllowedRoles limits who may connect. Empty means any role that already
	// passes the ownership check.
	AllowedRoles []string `bson:"allowed_roles,omitempty" json:"allowed_roles,omitempty"`

	// AllowedGroupIDs limits connection to members of these groups — the
	// directory groups synced from Entra, so an operator writes "only the
	// Support team" once and membership is maintained upstream.
	AllowedGroupIDs []string `bson:"allowed_group_ids,omitempty" json:"allowed_group_ids,omitempty"`

	// Which ways in are permitted. All three default to true on a new policy
	// so that saving one does not silently cut off a route nobody considered.
	AllowAttended   bool `bson:"allow_attended" json:"allow_attended"`
	AllowUnattended bool `bson:"allow_unattended" json:"allow_unattended"`
	AllowTerminal   bool `bson:"allow_terminal" json:"allow_terminal"`

	// TimeWindows restrict when a session may start. Empty means any time.
	// They gate the START only: a session already running is not cut off
	// mid-sentence because the clock struck six.
	TimeWindows []TimeWindow `bson:"time_windows,omitempty" json:"time_windows,omitempty"`

	RequireConsent bool `bson:"require_consent" json:"require_consent"`
	RequireReason  bool `bson:"require_reason" json:"require_reason"`

	// RequireRecording refuses the session outright when recording is not
	// configured, rather than letting an unrecorded one through. A policy that
	// says sessions are recorded has to mean it.
	RequireRecording bool `bson:"require_recording" json:"require_recording"`

	// MaxSessionMinutes caps a session's length. Zero means no cap.
	MaxSessionMinutes int `bson:"max_session_minutes" json:"max_session_minutes"`

	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
	CreatedBy string    `bson:"created_by,omitempty" json:"created_by,omitempty"`
	UpdatedBy string    `bson:"updated_by,omitempty" json:"updated_by,omitempty"`
}

// TimeWindow is a recurring span during which sessions may start.
type TimeWindow struct {
	// Days of the week, 0 = Sunday. Empty means every day.
	Days []int `bson:"days,omitempty" json:"days,omitempty"`

	// StartMinute and EndMinute are minutes from midnight in Timezone.
	//
	// Minutes rather than a "09:00" string because that is what comparison
	// needs, and parsing a time string at every connection attempt is a way to
	// fail open on a typo.
	StartMinute int `bson:"start_minute" json:"start_minute"`
	EndMinute   int `bson:"end_minute" json:"end_minute"`

	// Timezone is an IANA name. Empty means UTC — stated, because "business
	// hours" means nothing without one, and a support team in Pune working to
	// a window set in UTC would find it opened at half past two in the morning.
	Timezone string `bson:"timezone,omitempty" json:"timezone,omitempty"`
}

type ResourceStats struct {
	CPUPercent      float64 `bson:"cpu_percent" json:"cpu_percent"`
	MemoryPercent   float64 `bson:"memory_percent" json:"memory_percent"`
	DiskPercent     float64 `bson:"disk_percent" json:"disk_percent"`
	NetworkInbound  float64 `bson:"network_inbound" json:"network_inbound"`   // MB/s
	NetworkOutbound float64 `bson:"network_outbound" json:"network_outbound"` // MB/s
	Uptime          int64   `bson:"uptime_seconds" json:"uptime_seconds"`     // seconds
}

type LogEntry struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	MachineID primitive.ObjectID `bson:"machine_id" json:"machine_id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"` // Who executed it
	Username  string             `bson:"username" json:"username"`
	SessionID string             `bson:"session_id" json:"session_id"`
	Command   string             `bson:"command" json:"command"`
	Output    string             `bson:"output,omitempty" json:"output,omitempty"` // Command output/response
	Timestamp time.Time          `bson:"timestamp" json:"timestamp"`
	Success   bool               `bson:"success" json:"success"`
	Source    string             `bson:"source" json:"source"`         // "vscode", "cli", "ui"
	Browser   string             `bson:"browser" json:"browser"`       // User agent / browser info
	OSInfo    string             `bson:"os_info" json:"os_info"`       // Client OS info
	IPAddress string             `bson:"ip_address" json:"ip_address"` // Client IP
}

// Session represents a terminal session
type Session struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	SessionID    string             `bson:"session_id" json:"session_id"`
	MachineID    primitive.ObjectID `bson:"machine_id" json:"machine_id"`
	AgentID      string             `bson:"agent_id" json:"agent_id"`
	UserID       primitive.ObjectID `bson:"user_id" json:"user_id"`
	Username     string             `bson:"username" json:"username"`
	Source       string             `bson:"source" json:"source"`   // "vscode", "cli", "ui"
	Browser      string             `bson:"browser" json:"browser"` // User agent info
	OSInfo       string             `bson:"os_info" json:"os_info"` // Client OS
	IPAddress    string             `bson:"ip_address" json:"ip_address"`
	Status       string             `bson:"status" json:"status"` // "active", "closed"
	CommandCount int                `bson:"command_count" json:"command_count"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	ClosedAt     *time.Time         `bson:"closed_at,omitempty" json:"closed_at,omitempty"`
}

type DashboardStats struct {
	TotalMachines    int `json:"total_machines"`
	ActiveMachines   int `json:"active_machines"`
	InactiveMachines int `json:"inactive_machines"`
	TotalSessions    int `json:"total_sessions"`
}

type ActivityLog struct {
	ID          primitive.ObjectID `json:"id"`
	MachineID   primitive.ObjectID `json:"machine_id"`
	MachineName string             `json:"machine_name"`
	Command     string             `json:"command"`
	Success     bool               `json:"success"`
	Timestamp   time.Time          `json:"timestamp"`
}

// AuditLog records admin and system-level actions (user creation, config changes, etc.)
type AuditLog struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ActorID   string             `bson:"actor_id" json:"actor_id"`
	ActorName string             `bson:"actor_name" json:"actor_name"`
	ActorRole string             `bson:"actor_role" json:"actor_role"`

	// TenantID scopes the entry. Without it one organisation's audit trail
	// cannot be separated from another's, which makes the whole log unusable
	// for the compliance question it exists to answer.
	TenantID string `bson:"tenant_id" json:"tenant_id"`

	Action     string         `bson:"action" json:"action"`     // see the Audit* constants
	Resource   string         `bson:"resource" json:"resource"` // "machine", "policy", "application"
	ResourceID string         `bson:"resource_id" json:"resource_id"`
	Details    map[string]any `bson:"details,omitempty" json:"details,omitempty"`
	IPAddress  string         `bson:"ip_address" json:"ip_address"`
	Status     string         `bson:"status" json:"status"` // "success", "failure", "denied"
	Timestamp  time.Time      `bson:"timestamp" json:"timestamp"`

	// MachineName and AgentID are denormalised so a listing never needs a
	// join, and so the entry still reads correctly after a machine is removed.
	MachineName string `bson:"machine_name,omitempty" json:"machine_name,omitempty"`
	AgentID     string `bson:"agent_id,omitempty" json:"agent_id,omitempty"`
}

// EPM audit actions.
//
// The whole set is declared here, including the ones nothing emits yet, for
// two reasons. It is the contract the compliance report and the export filter
// against, so a reader can see what the product claims to record and what it
// does not. And when enforcement lands, those events slot into a pipeline that
// already exists rather than needing one designed around them.
const (
	// Deployment and policy distribution.
	AuditAgentRegistered = "agent.registered"
	AuditAgentUpdated    = "agent.updated"
	AuditPolicySynced    = "policy.synchronized"

	// Policy authoring. These are the "who changed the block rule, and when"
	// questions, and history is the one thing that cannot be retrofitted.
	AuditPolicyCreated = "policy.created"
	AuditPolicyUpdated = "policy.updated"
	AuditPolicyDeleted = "policy.deleted"

	// Application control. Emitted once enforcement exists; until then the
	// portal says plainly that nothing has been recorded rather than showing
	// an empty list that reads like "nothing was blocked".
	AuditAppAllowed  = "application.allowed"
	AuditAppBlocked  = "application.blocked"
	AuditAppElevated = "application.elevated"

	// AuditAppPolicyViolation is detection, not enforcement: an application
	// matching a block or elevate rule has been found installed. It is named
	// apart from AuditAppBlocked on purpose — calling it "blocked" would read
	// as evidence that execution was prevented, which it was not.
	AuditAppPolicyViolation = "application.policy_violation"

	// Just-in-time access.
	AuditJITRequested = "jit.requested"
	AuditJITApproved  = "jit.approved"
	AuditJITRejected  = "jit.rejected"
	AuditJITExpired   = "jit.expired"

	// Sudo. Also awaiting enforcement.
	AuditSudoExecuted = "sudo.executed"
	AuditSudoDenied   = "sudo.denied"

	// Remote access.
	AuditRemoteStarted = "remote_control.start"
	AuditRemoteStopped = "remote_control.stop"
	AuditRemoteRefused = "remote_access.refused"

	// Inventory.
	AuditInventoryReported = "inventory.reported"

	// AuditInventoryScanRequested records an operator asking for a scan, which
	// is a separate fact from the scan arriving: a request with no
	// inventory.reported after it is how "the agent is connected but wedged"
	// shows up in the trail.
	AuditInventoryScanRequested = "inventory.scan_requested"
)

// AuditQuery filters an audit listing.
type AuditQuery struct {
	TenantID string
	Actions  []string
	Actor    string
	AgentID  string
	Status   string
	Search   string
	From, To time.Time
	Limit    int
	Skip     int
}

type Issue struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Title       string             `bson:"title" json:"title"`
	Description string             `bson:"description" json:"description"`
	Status      string             `bson:"status" json:"status"` // "open", "in_progress", "closed"
	AuthorID    primitive.ObjectID `bson:"author_id" json:"author_id"`
	AuthorName  string             `bson:"author_name" json:"author_name"`
	Images      []string           `bson:"images" json:"images"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
	FixCount    int                `bson:"fix_count" json:"fix_count"`
}

type Fix struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	IssueID    primitive.ObjectID `bson:"issue_id" json:"issue_id"`
	AuthorID   primitive.ObjectID `bson:"author_id" json:"author_id"`
	AuthorName string             `bson:"author_name" json:"author_name"`
	Content    string             `bson:"content" json:"content"`
	Images     []string           `bson:"images" json:"images"`
	Likes      int                `bson:"likes" json:"likes"`
	LikedBy    []string           `bson:"liked_by" json:"liked_by"` // Array of usernames
	IsAccepted bool               `bson:"is_accepted" json:"is_accepted"`
	CreatedAt  time.Time          `bson:"created_at" json:"created_at"`
}

// S3Config holds S3-compatible storage configuration per tenant
type S3Config struct {
	Enabled   bool   `bson:"enabled" json:"enabled"`
	Endpoint  string `bson:"endpoint" json:"endpoint"` // e.g. "s3.amazonaws.com" or "minio.host:9000"
	Protocol  string `bson:"protocol" json:"protocol"` // "http" or "https"
	AccessKey string `bson:"access_key" json:"access_key"`
	SecretKey string `bson:"secret_key" json:"secret_key"`
	Bucket    string `bson:"bucket" json:"bucket"`
	Region    string `bson:"region" json:"region"` // AWS region or "" for custom endpoints
}

// LogManagementConfig holds global log retention and archival settings (single document, no tenantID).
type LogManagementConfig struct {
	ID               primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	RetentionDays    int                `bson:"retention_days" json:"retention_days"` // 0 = never auto-delete
	ArchiveEnabled   bool               `bson:"archive_enabled" json:"archive_enabled"`
	ArchiveEveryDays int                `bson:"archive_every_days" json:"archive_every_days"` // 10, 20, 30
	StorageType      string             `bson:"storage_type" json:"storage_type"`             // "s3","gcs","azure","sftp","nfs","elasticsearch","siem",""
	StorageCredsEnc  []byte             `bson:"storage_creds_enc,omitempty" json:"-"`         // AES-GCM encrypted JSON
	LastArchiveAt    *time.Time         `bson:"last_archive_at,omitempty" json:"last_archive_at,omitempty"`
	NextArchiveAt    *time.Time         `bson:"next_archive_at,omitempty" json:"next_archive_at,omitempty"`
	UpdatedAt        time.Time          `bson:"updated_at" json:"updated_at"`
}

// ArchiveRun tracks a single log archival job execution.
type ArchiveRun struct {
	ID               primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	StartedAt        time.Time          `bson:"started_at" json:"started_at"`
	FinishedAt       *time.Time         `bson:"finished_at,omitempty" json:"finished_at,omitempty"`
	Status           string             `bson:"status" json:"status"` // "running","success","failed","partial"
	StorageType      string             `bson:"storage_type" json:"storage_type"`
	Trigger          string             `bson:"trigger" json:"trigger"` // "auto","manual"
	LogsArchived     int64              `bson:"logs_archived" json:"logs_archived"`
	SessionsArchived int64              `bson:"sessions_archived" json:"sessions_archived"`
	LogsDeleted      int64              `bson:"logs_deleted" json:"logs_deleted"`
	BytesArchived    int64              `bson:"bytes_archived" json:"bytes_archived"`
	ArchiveKey       string             `bson:"archive_key" json:"archive_key"`
	// ArchiveKeys holds every object a run wrote. A run that spans several
	// batches writes several objects, and recording only one of them made all
	// but that one unrestorable.
	ArchiveKeys []string `bson:"archive_keys,omitempty" json:"archive_keys,omitempty"`
	ErrorMsg    string   `bson:"error_msg,omitempty" json:"error_msg,omitempty"`
}

// TenantConfig holds per-tenant settings stored in agent-backend
type TenantConfig struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	TenantID    string             `bson:"tenant_id" json:"tenant_id"`
	S3          S3Config           `bson:"s3" json:"s3"`
	LogShipping LogShippingConfig  `bson:"log_shipping" json:"log_shipping"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

// AgentPayload renders the policy in the exact shape the agent unmarshals.
//
// It lives on the type so every sender uses one spelling of these keys. They
// are the agent's own config-file keys, and getting one wrong does not fail —
// encoding/json simply leaves that field at its zero value, so a typo here
// would quietly turn a setting off on the whole fleet.
func (c LogShippingConfig) AgentPayload() map[string]any {
	return map[string]any{
		"enabled":            c.Enabled,
		"system_logs":        c.SystemLogs,
		"websites":           c.Websites,
		"interval_seconds":   c.IntervalSeconds,
		"daily_budget_mb":    c.DailyBudgetMB,
		"backfill_hours":     c.BackfillHours,
		"include_info_debug": c.IncludeInfoDebug,
		"keep_raw":           c.KeepRaw,
		"windows_channels":   c.WindowsChannels,
	}
}

// LogShippingConfig is the tenant-wide policy for collecting each machine's own
// system logs. It mirrors the agent-side struct field for field, because it is
// serialised straight to the agent over the gRPC command channel.
//
// It is stored per tenant rather than per machine so a fleet is configured
// once; the archive destination is the tenant's S3 config, and collection does
// nothing useful without one.
type LogShippingConfig struct {
	Enabled          bool     `bson:"enabled" json:"enabled"`
	SystemLogs       bool     `bson:"system_logs" json:"system_logs"`
	Websites         bool     `bson:"websites" json:"websites"`
	IntervalSeconds  int      `bson:"interval_seconds" json:"interval_seconds"`
	DailyBudgetMB    int      `bson:"daily_budget_mb" json:"daily_budget_mb"`
	BackfillHours    int      `bson:"backfill_hours" json:"backfill_hours"`
	IncludeInfoDebug bool     `bson:"include_info_debug" json:"include_info_debug"`
	KeepRaw          bool     `bson:"keep_raw" json:"keep_raw"`
	WindowsChannels  []string `bson:"windows_channels,omitempty" json:"windows_channels,omitempty"`
}

// SessionRecording tracks a terminal session recording stored in S3
type SessionRecording struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	SessionID   string             `bson:"session_id" json:"session_id"`
	MachineID   primitive.ObjectID `bson:"machine_id" json:"machine_id"`
	MachineName string             `bson:"machine_name" json:"machine_name"`
	TenantID    string             `bson:"tenant_id" json:"tenant_id"`
	Username    string             `bson:"username" json:"username"`
	S3Key       string             `bson:"s3_key" json:"s3_key"`
	SizeBytes   int64              `bson:"size_bytes" json:"size_bytes"`
	Duration    int64              `bson:"duration_seconds" json:"duration_seconds"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
}

// AccessAsks is everything one request is asking for.
//
// A set of independent asks rather than one choice. Somebody diagnosing a
// crash often needs to watch the screen AND install a debugger, and making
// that two requests means two approvals, two audit entries, and two windows
// that have to be made to overlap by hand.
type AccessAsks struct {
	RemoteSupport *RemoteSupportAsk `bson:"remote_support,omitempty" json:"remote_support,omitempty"`
	AdminAccess   *AdminAccessAsk   `bson:"admin_access,omitempty" json:"admin_access,omitempty"`
	AppInstall    *AppInstallAsk    `bson:"app_install,omitempty" json:"app_install,omitempty"`
}

// RemoteSupportAsk: see or drive the machine.
type RemoteSupportAsk struct {
	// Reason is what will happen in this session, in the requester's words.
	Reason string `bson:"reason,omitempty" json:"reason,omitempty"`
	// Control is how much of the machine: watching it, or driving it.
	//
	// The person whose desktop it is cares which one was given, and an
	// approver handing out full control believing it was view-only is the
	// mistake this field exists to prevent.
	Control string `bson:"control,omitempty" json:"control,omitempty"`
}

// AdminAccessAsk: administrator rights on the machine.
type AdminAccessAsk struct {
	Reason string `bson:"reason,omitempty" json:"reason,omitempty"`
}

// AppInstallAsk: permission to install named software.
type AppInstallAsk struct {
	Reason string `bson:"reason,omitempty" json:"reason,omitempty"`
	// Applications names what may be installed.
	//
	// Named rather than left open, because "may install software" and "may
	// install Docker Desktop" are different grants, and only the second is
	// one an approver can actually weigh.
	Applications []string `bson:"applications,omitempty" json:"applications,omitempty"`
}

// Any reports whether this request asks for anything at all.
func (a AccessAsks) Any() bool {
	return a.RemoteSupport != nil || a.AdminAccess != nil || a.AppInstall != nil
}

// What an access request is asking for.
const (
	// AccessTypeRemoteSupport: somebody needs to see or drive the machine to
	// fix something.
	AccessTypeRemoteSupport = "remote_support"
	// AccessTypeAdmin: administrator rights on the machine.
	AccessTypeAdmin = "admin_access"
	// AccessTypeInstall: permission to install one piece of software.
	AccessTypeInstall = "application_installation"
)

// How much control an access request is asking for.
const (
	// AccessLevelView: watch the screen, drive nothing. Enough to diagnose.
	AccessLevelView = "view_only"
	// AccessLevelControl: full control of the desktop, over VNC or RDP.
	AccessLevelControl = "full_control"
)

type AccessRequest struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	MachineID         primitive.ObjectID `bson:"machine_id" json:"machine_id"`
	MachineName       string             `bson:"machine_name" json:"machine_name"`
	MachineAgentID    string             `bson:"machine_agent_id" json:"machine_agent_id"`
	RequesterID       string             `bson:"requester_id" json:"requester_id"`
	RequesterUsername string             `bson:"requester_username" json:"requester_username"`
	RequesterEmail    string             `bson:"requester_email" json:"requester_email"`
	TenantID          string             `bson:"tenant_id" json:"tenant_id"`
	OwnerID           string             `bson:"owner_id" json:"owner_id"`
	OwnerEmail        string             `bson:"owner_email" json:"owner_email"` // for email notification
	// Title is the one line an approver sees in a queue of them.
	//
	// RequestNote is the reasoning and can run to paragraphs; a list needs
	// something short enough to scan. Without it the queue showed a machine
	// name and a duration, and telling two requests apart meant opening both.
	Title string `bson:"title,omitempty" json:"title,omitempty"`

	RequestNote string `bson:"request_note" json:"request_note"`

	// DurationHours is kept only to read requests stored before durations
	// were counted in minutes. Nothing writes it any more; use Minutes().
	DurationHours int `bson:"duration_hours,omitempty" json:"duration_hours,omitempty"`

	// DurationMinutes is how long the grant lasts once approved.
	//
	// Minutes, because the product asks for fifteen-minute access and hours
	// could not express it — anything under an hour rounded to zero, and zero
	// meant NEVER EXPIRES. The shortest window on the list handed out
	// permanent access, which is the exact opposite of what somebody picking
	// it was asking for.
	//
	// Zero is no longer overloaded: it means "not set", and a request with no
	// duration is refused rather than granted for ever.
	DurationMinutes int `bson:"duration_minutes,omitempty" json:"duration_minutes,omitempty"`

	// Asks is WHAT is being requested. One request can carry more than one.
	//
	// It was a single AccessType, which forced somebody who needed to watch a
	// screen AND install something to raise two requests, or to pick one and
	// explain the rest in the note — where no approver could act on it and no
	// audit trail recorded it. Each ask carries its own reason, because "why
	// do you need admin rights" and "why do you need to see the screen" have
	// different answers and an approver weighs them separately.
	Asks AccessAsks `bson:"asks,omitempty" json:"asks,omitempty"`

	// AccessType and AccessLevel are read only for requests stored before
	// Asks existed. Nothing writes them.
	AccessType  string `bson:"access_type,omitempty" json:"access_type,omitempty"`
	AccessLevel string `bson:"access_level,omitempty" json:"access_level,omitempty"`

	// NotBefore and NotAfter are the window the session may run in.
	//
	// Distinct from the approval time: somebody can ask on Monday for a
	// window on Saturday, and an approver deciding on Monday should not start
	// the clock then. Both nil means "as soon as it is approved, for the
	// duration asked for".
	NotBefore     *time.Time `bson:"not_before,omitempty" json:"not_before,omitempty"`
	NotAfter      *time.Time `bson:"not_after,omitempty" json:"not_after,omitempty"`
	Status        string     `bson:"status" json:"status"` // "pending","approved","rejected","expired","revoked"
	ApprovedBy    string     `bson:"approved_by,omitempty" json:"approved_by,omitempty"`
	ApprovedAt    *time.Time `bson:"approved_at,omitempty" json:"approved_at,omitempty"`
	ExpiresAt     *time.Time `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
	RejectedBy    string     `bson:"rejected_by,omitempty" json:"rejected_by,omitempty"`
	RejectComment string     `bson:"reject_comment,omitempty" json:"reject_comment,omitempty"`
	RevokedBy     string     `bson:"revoked_by,omitempty" json:"revoked_by,omitempty"`
	RevokedAt     *time.Time `bson:"revoked_at,omitempty" json:"revoked_at,omitempty"`
	RequestedAt   time.Time  `bson:"requested_at" json:"requested_at"`
	UpdatedAt     time.Time  `bson:"updated_at" json:"updated_at"`
}

type Store interface {
	// User management is handled by vsay-auth service
	// All user data comes via headers (X-Username, X-User-ID, X-User-Email, etc.)

	// Machine registration flow
	CreatePendingMachine(machine *Machine) error
	GetMachineByRegistrationToken(token string) (*Machine, error)
	RevokeMachine(machineID primitive.ObjectID) error      // Marks revoked=true; blocks future sign-cert + gRPC
	UpdateCertFingerprint(token, fingerprint string) error // Stores SHA-256 of last issued agent cert
	GetMachineByName(name string, ownerID primitive.ObjectID) (*Machine, error)
	ActivateMachine(token string, agentID string, osInfo string, ipAddress string, metadata map[string]string, initialStatus string) error

	RegisterMachine(machine *Machine) error
	GetMachineByAgentID(agentID string) (*Machine, error)
	GetMachineByID(machineID primitive.ObjectID) (*Machine, error)
	GetMachinesByOwner(ownerID primitive.ObjectID) ([]*Machine, error)
	GetMachinesSharedWithUser(username string) ([]*Machine, error)
	GetAllMachines() ([]*Machine, error)
	GetMachinesByTenantID(tenantID string) ([]*Machine, error)
	// CountMachinesByStatus returns per-status counts using index-only scans.
	// Use this instead of GetAllMachines() when you only need counts.
	CountMachinesByStatus() (online, offline, pending int64, err error)
	UpdateMachineStatus(agentID string, status string, lastActive time.Time) error
	UpdateMachineStats(agentID string, stats ResourceStats) error
	// UpdateMachineHeartbeat combines status + stats into a single MongoDB write.
	// Prefer this over calling UpdateMachineStatus + UpdateMachineStats separately.
	UpdateMachineHeartbeat(agentID string, lastActive time.Time, stats ResourceStats) error
	MarkInactiveMachinesOffline(inactiveThreshold time.Duration) error
	// MarkAllMachinesOffline flips every "online" machine to "offline". Called on
	// backend startup: a freshly-started process holds no agent connections, so any
	// lingering "online" status from a previous process is stale. Live agents
	// reconnect within seconds and set themselves back online.
	MarkAllMachinesOffline() error
	DeleteMachine(machineID primitive.ObjectID) error
	GrantMachineAccess(machineID primitive.ObjectID, username string) error
	RevokeMachineAccess(machineID primitive.ObjectID, username string) error
	AddMachineToGroup(agentID string, groupID string) error
	RemoveMachineFromGroup(agentID string, groupID string) error

	CreateLog(log *LogEntry) error
	UpdateLogOutput(logID primitive.ObjectID, output string) error
	GetLogsByMachine(machineID primitive.ObjectID, limit int) ([]*LogEntry, error)
	GetLogsByMachinePaged(machineID primitive.ObjectID, limit, skip int) ([]*LogEntry, error)
	CountLogsByMachine(machineID primitive.ObjectID) (int64, error)
	GetLogsBySession(sessionID string) ([]*LogEntry, error)
	GetLogsBySessionPaged(sessionID string, limit, skip int) ([]*LogEntry, error)
	CountLogsBySession(sessionID string) (int64, error)
	SearchLogsByMachinePaged(machineID primitive.ObjectID, query string, limit, skip int) ([]*LogEntry, int64, error)
	DeleteLogsByMachine(machineID primitive.ObjectID) error

	// Session management
	CreateSession(session *Session) error
	GetSessionByID(sessionID string) (*Session, error)
	GetSessionsByMachine(machineID primitive.ObjectID) ([]*Session, error)
	GetSessionsByMachinePaged(machineID primitive.ObjectID, limit, skip int) ([]*Session, error)
	CountSessionsByMachine(machineID primitive.ObjectID) (int64, error)
	GetActiveSessionsByMachine(machineID primitive.ObjectID) ([]*Session, error)
	GetSessionsByUser(userID primitive.ObjectID) ([]*Session, error)
	UpdateSessionStatus(sessionID string, status string) error
	CloseSession(sessionID string) error
	IncrementSessionCommandCount(sessionID string) error

	GetDashboardStats(ownerID primitive.ObjectID) (*DashboardStats, error)
	GetRecentMachines(ownerID primitive.ObjectID, limit int) ([]*Machine, error)
	GetRecentActivity(ownerID primitive.ObjectID, limit int) ([]*ActivityLog, error)

	// Community/Issues
	CreateIssue(issue *Issue) error
	GetIssueByID(issueID primitive.ObjectID) (*Issue, error)
	GetAllIssues(limit, skip int) ([]*Issue, error)
	UpdateIssue(issueID primitive.ObjectID, updates map[string]interface{}) error
	DeleteIssue(issueID primitive.ObjectID) error
	IncrementIssueFixCount(issueID primitive.ObjectID) error

	// Fixes
	CreateFix(fix *Fix) error
	GetFixesByIssue(issueID primitive.ObjectID) ([]*Fix, error)
	GetFixByID(fixID primitive.ObjectID) (*Fix, error)
	UpdateFix(fixID primitive.ObjectID, updates map[string]interface{}) error
	DeleteFix(fixID primitive.ObjectID) error
	LikeFix(fixID primitive.ObjectID, username string) error
	UnlikeFix(fixID primitive.ObjectID, username string) error
	MarkFixAsAccepted(fixID primitive.ObjectID, issueID primitive.ObjectID) error

	// Tenant configuration (S3, etc.)
	GetTenantConfig(tenantID string) (*TenantConfig, error)
	UpsertTenantConfig(config *TenantConfig) error

	// Session recordings
	CreateRecording(recording *SessionRecording) error
	GetRecordingsByMachine(machineID primitive.ObjectID, limit, skip int) ([]*SessionRecording, error)
	CountRecordingsByMachine(machineID primitive.ObjectID) (int64, error)
	GetRecordingByID(id primitive.ObjectID) (*SessionRecording, error)

	// Log management configuration + archival
	GetLogManagementConfig() (*LogManagementConfig, error)
	UpsertLogManagementConfig(cfg *LogManagementConfig) error
	GetLogsOlderThan(before time.Time, limit int) ([]*LogEntry, error)
	DeleteLogsByIDs(ids []primitive.ObjectID) (int64, error)
	GetSessionsOlderThan(before time.Time, limit int) ([]*Session, error)
	DeleteSessionsByIDs(ids []primitive.ObjectID) (int64, error)
	GetAuditLogsOlderThan(before time.Time, limit int) ([]*AuditLog, error)
	GetAuditLogs(q AuditQuery) ([]*AuditLog, error)
	CountAuditLogs(q AuditQuery) (int64, error)
	StreamAuditLogs(ctx context.Context, q AuditQuery, fn func(*AuditLog) error) error
	CountAuditByAction(q AuditQuery) ([]AuditActionCount, error)
	CountAuditByActor(q AuditQuery, limit int) ([]AuditActorCount, error)
	DeleteAuditLogsByIDs(ids []primitive.ObjectID) (int64, error)
	CreateAuditLog(log *AuditLog) error
	CreateArchiveRun(run *ArchiveRun) error
	GetArchiveRuns(limit int) ([]*ArchiveRun, error)
	GetArchiveRunByID(id primitive.ObjectID) (*ArchiveRun, error)
	UpdateArchiveRunFinished(id primitive.ObjectID, status, errMsg string, logsArchived, sessionsArchived, logsDeleted, bytesArchived int64, archiveKeys []string) error

	// Access requests
	CreateAccessRequest(req *AccessRequest) error
	GetAccessRequestsByMachine(machineID primitive.ObjectID) ([]*AccessRequest, error)
	GetAccessRequestsByRequester(requesterID, tenantID string) ([]*AccessRequest, error)
	GetAccessRequestByID(id primitive.ObjectID) (*AccessRequest, error)
	UpdateAccessRequest(req *AccessRequest) error
	GetExpiredAccessRequests() ([]*AccessRequest, error)
	// GetAccessRequestsFiltered powers the admin-facing Access Requests page: one
	// status tab at a time (pending/approved/expired/rejected/revoked), optionally
	// scoped to a tenant and text-searched across requester/machine fields.
	GetAccessRequestsFiltered(tenantID, status, search string, limit, skip int) ([]*AccessRequest, int64, error)

	// External access events (SSH/RDP intrusion tracking)
	CreateAccessEvent(ev *AccessEvent) error
	HasActiveAccessEvent(agentID, osUser, line string) (bool, error)
	CloseStaleAccessEvents(agentID string, keep []AccessEventKey, at time.Time) (int64, error)
	DedupeActiveAccessEvents(agentID string, at time.Time) (int64, error)
	CloseAccessEvent(agentID, osUser, line string, logoutAt time.Time) error
	GetActiveAccessEvents(machineID primitive.ObjectID) ([]*AccessEvent, error)
	GetAccessEventsByMachine(machineID primitive.ObjectID, limit, skip int) ([]*AccessEvent, error)
	CountAccessEventsByMachine(machineID primitive.ObjectID) (int64, error)

	// Installed-application inventory.
	//
	// The write path is deliberately two calls: chunks are upserted as they
	// arrive, and the removal sweep runs separately and only for a complete
	// scan. Folding them together would make it possible to mark software
	// removed on the strength of a partial report.
	UpsertInventoryChunk(machine *Machine, scanID string, apps []InstalledApp, at time.Time) (added, updated int64, newApps []InstalledApp, err error)
	SweepRemovedApps(agentID, scanID string, at time.Time) (int64, error)
	CreateInventoryScan(scan *InventoryScan) error
	UpdateInventoryScan(agentID, scanID string, added, updated, removed int64, reported int, complete bool, at time.Time) error
	GetLatestInventoryScan(agentID string) (*InventoryScan, error)
	GetInstalledAppsByMachine(machineID primitive.ObjectID, q InventoryQuery) ([]*InstalledApp, error)
	CountInstalledAppsByMachine(machineID primitive.ObjectID, q InventoryQuery) (int64, error)
	StreamInstalledAppsByTenant(ctx context.Context, tenantID string, fn func(*InstalledApp) error) error
	GetAppCatalog(tenantID string, q CatalogQuery) ([]CatalogEntry, int64, error)
	GetMachinesWithApp(tenantID, name, publisher string, limit, skip int) ([]*InstalledApp, int64, error)
	GetInventoryCoverage(tenantID string, staleAfter time.Duration) (InventoryCoverage, error)

	// Application-control policies.
	GetAppControlSettings(tenantID string) (*AppControlSettings, error)
	SetAppControlEnforcement(tenantID string, enabled bool, actor string) error
	RecordEnforcementEvents(events []EnforcementEvent) error
	GetEnforcementEvents(q EnforcementEventQuery) ([]*EnforcementEvent, int64, error)

	// ClaimNotification reserves the right to send one notification, so a
	// standing condition reported every few minutes is mailed once.
	ClaimNotification(key string, cooldown time.Duration) (bool, error)
	CountEnforcementByMechanism(tenantID string, from, to time.Time) (map[EnforcementCount]int64, error)
	DeleteEnforcementEventsByMachine(machineID primitive.ObjectID) error

	CreateAppPolicy(p *AppPolicy) error
	UpdateAppPolicy(p *AppPolicy) error
	DeleteAppPolicy(tenantID string, id primitive.ObjectID) error
	GetAppPolicyByID(tenantID string, id primitive.ObjectID) (*AppPolicy, error)
	GetAppPoliciesByTenant(tenantID string) ([]*AppPolicy, error)

	// Remote-access policies.
	CreateRemoteAccessPolicy(p *RemoteAccessPolicy) error
	UpdateRemoteAccessPolicy(p *RemoteAccessPolicy) error
	DeleteRemoteAccessPolicy(tenantID string, id primitive.ObjectID) error
	GetRemoteAccessPolicyByID(tenantID string, id primitive.ObjectID) (*RemoteAccessPolicy, error)
	GetRemoteAccessPoliciesByTenant(tenantID string) ([]*RemoteAccessPolicy, error)
	AddMachineNotifyEmail(machineID primitive.ObjectID, email string) error

	// Agent process stats (Agent Monitoring)
	UpsertAgentStats(agentID string, stats *AgentStats) error

	// Health / readiness
	Ping(ctx context.Context) error
}

// Minutes is how long this grant lasts, whichever field it was stored in.
//
// Requests written before durations were counted in minutes carry hours, and
// in that encoding zero meant NEVER EXPIRES. That meaning is preserved only
// for those old rows — a new request with no duration is refused at the API,
// not stored and granted for ever.
func (a *AccessRequest) Minutes() int {
	if a.DurationMinutes > 0 {
		return a.DurationMinutes
	}
	return a.DurationHours * 60
}

// NeverExpires reports whether this is one of the old unbounded grants.
//
// Only true for a request stored in the hours encoding with a zero duration.
// Nothing can create one now, and they are worth naming rather than leaving
// as a silent property of the number zero.
func (a *AccessRequest) NeverExpires() bool {
	return a.DurationMinutes == 0 && a.DurationHours == 0
}

// DescribeAsks puts a request's asks into one line, for the audit trail.
//
// The audit entry has to say WHAT was approved. "approved an access request"
// records that a decision happened and nothing about what was handed over,
// which is the half that matters when somebody asks later who gave out
// administrator rights.
func DescribeAsks(a AccessAsks) string {
	parts := make([]string, 0, 3)
	if a.RemoteSupport != nil {
		what := "remote support"
		if a.RemoteSupport.Control == AccessLevelControl {
			what += " (full control)"
		} else {
			what += " (view only)"
		}
		parts = append(parts, what)
	}
	if a.AdminAccess != nil {
		parts = append(parts, "admin access")
	}
	if a.AppInstall != nil {
		parts = append(parts,
			"install: "+strings.Join(a.AppInstall.Applications, ", "))
	}
	if len(parts) == 0 {
		// A request stored before asks existed. Named rather than left blank,
		// because an empty field in an audit entry reads as a bug.
		return "not recorded"
	}
	return strings.Join(parts, "; ")
}
