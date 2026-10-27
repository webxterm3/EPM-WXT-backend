package grpc

import (
	"strings"
	"testing"
)

// An endpoint's request for blocked software crosses two repositories: the
// agent sends a discriminator, this handles it, and the approval comes back
// as a field on the policy push.
//
// None of those three fails to compile when another is renamed. The button
// would simply stop producing requests, and the person who pressed it would
// be told it had worked.
func TestTheInstallRequestContractMatchesTheAgent(t *testing.T) {
	src := readAgentSource(t, "internal/agent/pendinginstall.go")

	want := `InstallRequestDiscriminator = "` + InstallRequestDiscriminator + `"`
	if !strings.Contains(src, want) {
		t.Errorf("the agent no longer sends %q", InstallRequestDiscriminator)
	}

	// The payload this handler decodes, field by field. A renamed json tag
	// decodes to the zero value: the request would be raised with no
	// application name and dropped, silently.
	for _, field := range []string{
		`json:"application"`, `json:"publisher"`, `json:"bundle_id"`, `json:"os_user"`,
		`json:"os_user_email"`, `json:"install_path,omitempty"`,
	} {
		if !strings.Contains(src, field) {
			t.Errorf("the agent no longer sends %s", field)
		}
	}
}

// The approval travels back as a NEW field on the policy payload. An agent
// that predates it ignores it and keeps blocking, which is the direction this
// has to fail in — the other way round, an old agent would half-understand a
// changed field and allow something indefinitely.
func TestTheApprovalReachesTheAgentAsItsOwnField(t *testing.T) {
	src := readAgentSource(t, "internal/apppolicy/policy.go")

	for _, want := range []string{
		`json:"approved_installs,omitempty"`,
		"func (e *Effective) InstallApproved(",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the agent no longer understands %q, so approving a request "+
				"would record a decision that never reaches the machine", want)
		}
	}

	// And the endpoint must still require a signature before honouring one.
	decide := readAgentSource(t, "internal/pendinginstall/decide.go")
	if !strings.Contains(decide, "app.Publisher != \"\"") {
		t.Error("the endpoint no longer requires a verified signature before " +
			"honouring an approval — a name-only approval would then be claimable " +
			"by any bundle with a matching folder name")
	}
}

// The result travels back on its own tag, and the backend decodes a payload
// the agent writes. Neither side fails to compile when the other is renamed:
// requests would simply stop being completed, and nothing would say why.
func TestTheInstallResultContractMatchesTheAgent(t *testing.T) {
	src := readAgentSource(t, "internal/agent/pendinginstall.go")

	want := `InstallResultDiscriminator = "` + InstallResultDiscriminator + `"`
	if !strings.Contains(src, want) {
		t.Errorf("the agent no longer sends %q", InstallResultDiscriminator)
	}
	for _, field := range []string{
		`json:"application"`, `json:"bundle_id"`, `json:"problem,omitempty"`,
	} {
		if !strings.Contains(src, field) {
			t.Errorf("the agent no longer sends %s on the result", field)
		}
	}

	// And it must actually be sent, not merely declared.
	if !strings.Contains(src, "SendStatusUpdate(InstallResultDiscriminator") {
		t.Error("the agent declares the result tag but never sends it, so every " +
			"approved request stays Active until its window runs out")
	}
}

// The operation travels on the approval, as a NEW field.
//
// An agent that predates it ignores it and reads every approval as the
// install approval it already understood — which is the direction a version
// mismatch has to fail in. The other way round, an old agent would see a
// remove-only approval and treat it as permission to install.
func TestTheOperationReachesTheAgentAsItsOwnField(t *testing.T) {
	src := readAgentSource(t, "internal/apppolicy/policy.go")

	if !strings.Contains(src, `json:"operation,omitempty"`) {
		t.Error("the agent does not read the operation, so a remove-only " +
			"approval is read as permission to install")
	}
	for _, op := range []string{`OpInstall = "install"`, `OpUpdate  = "update"`, `OpRemove  = "remove"`} {
		if !strings.Contains(src, op) {
			t.Errorf("the agent no longer defines %s", op)
		}
	}
	// And it must actually gate on it.
	if !strings.Contains(src, "a.permits(") {
		t.Error("the agent reads the operation but never tests it")
	}
}
