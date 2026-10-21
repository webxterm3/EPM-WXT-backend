package grpc

import (
	"testing"
	"time"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// A failed `elevate` and a failed `elevate-launch` are opposite facts, and the
// first version of this routing treated them as one.
//
//	elevate/failed        — the machine cannot honour a rule somebody wrote.
//	                        The administrator's own configuration.
//	elevate-launch/failed — a launch asked for administrator rights and policy
//	                        said no. Somebody is trying something forbidden.
//
// Mailing the second as the first tells an administrator their rule is broken
// at the exact moment somebody is probing it, and sends them off to repair
// something that is working correctly.
func TestARefusedAttemptIsNotReportedAsABrokenRule(t *testing.T) {
	kind, cooldown, ok := classifyElevation(store.EnforceElevateLaunch, store.OutcomeFailed)

	if !ok {
		t.Fatal("a refused elevation attempt produced no alert at all")
	}
	if kind == elevationUnavailable {
		t.Fatal("a refused attempt was classified as a rule that cannot be honoured — " +
			"the administrator would be told their configuration is broken while " +
			"somebody is probing it")
	}
	if kind != elevationRefused {
		t.Errorf("classified as %q, want %q", kind, elevationRefused)
	}
	// What matters about a refusal is that it keeps happening. A long window
	// reports a hundred attempts as one.
	if cooldown >= elevationUnavailableCooldn {
		t.Errorf("refusals are suppressed for %v, as long as a standing condition — "+
			"repetition is the signal and this hides it", cooldown)
	}
}

func TestEveryElevationOutcomeIsRoutedToItsOwnMessage(t *testing.T) {
	cases := []struct {
		mechanism, outcome, want string
	}{
		{store.EnforceElevate, store.OutcomeApplied, elevationGranted},
		{store.EnforceElevateLaunch, store.OutcomeApplied, elevationLaunched},
		{store.EnforceElevate, store.OutcomeFailed, elevationUnavailable},
		{store.EnforceElevateLaunch, store.OutcomeFailed, elevationRefused},
	}

	seen := map[string]bool{}
	for _, c := range cases {
		got, _, ok := classifyElevation(c.mechanism, c.outcome)
		if !ok {
			t.Errorf("%s/%s produced no alert", c.mechanism, c.outcome)
			continue
		}
		if got != c.want {
			t.Errorf("%s/%s classified as %q, want %q", c.mechanism, c.outcome, got, c.want)
		}
		if seen[got] {
			t.Errorf("%s/%s reuses the kind %q — two different facts would be "+
				"suppressed by one another's claim", c.mechanism, c.outcome, got)
		}
		seen[got] = true
	}
}

// Everything else an endpoint reports is a restriction. Alerting on those
// would mean a mail for every blocked launch on every machine, which is how
// an alert becomes a filter rule.
func TestOnlyElevationIsAlerted(t *testing.T) {
	quiet := []struct{ mechanism, outcome string }{
		{store.EnforceLock, store.OutcomeApplied},
		{store.EnforceTerminate, store.OutcomeApplied},
		{store.EnforceQuarantine, store.OutcomeApplied},
		{store.EnforceUnlock, store.OutcomeApplied},
		{store.EnforceRefused, store.OutcomeFailed},
		{store.EnforceElevate, store.OutcomeSkipped},
		{"", ""},
	}
	for _, c := range quiet {
		if _, _, ok := classifyElevation(c.mechanism, c.outcome); ok {
			t.Errorf("%s/%s raised an elevation alert", c.mechanism, c.outcome)
		}
	}
}

// The cooldowns encode a judgement about each message, and swapping two of
// them silently changes how much of the fleet's activity is reported.
func TestCooldownsMatchWhatEachMessageReports(t *testing.T) {
	_, standing, _ := classifyElevation(store.EnforceElevate, store.OutcomeFailed)
	_, attempt, _ := classifyElevation(store.EnforceElevateLaunch, store.OutcomeFailed)
	_, granted, _ := classifyElevation(store.EnforceElevate, store.OutcomeApplied)

	if !(attempt < granted && granted < standing) {
		t.Errorf("cooldowns are attempt=%v granted=%v standing=%v; an attempt must be "+
			"reported most readily and a standing condition least, or the quiet "+
			"message drowns the urgent one", attempt, granted, standing)
	}
	if attempt > time.Hour {
		t.Errorf("a refused attempt is suppressed for %v — too long to show repetition", attempt)
	}
}
