// Package policy decides what an application-control policy says about a
// given application.
//
// Nothing here talks to a database or a network. Resolution and matching are
// pure functions over values, which is what lets the rules below — precedence,
// conflict handling, and above all the fail-closed empty-criteria rule — be
// tested exhaustively rather than reasoned about.
//
// In Phase A the result is only ever reported, never enforced.
package policy

import (
	"path/filepath"
	"strings"

	"github.com/vsay/vsay-agent-backend/internal/store"
)

// matchField reports whether one value satisfies one field's criteria.
//
// An unset field constrains nothing and therefore matches — that is what makes
// "publisher = Acme" a rule about publishers rather than a rule that also
// requires an empty name. The caller is responsible for rejecting criteria
// where EVERY field is unset; see MatchCriteria.Empty and matches below.
func matchField(m store.StringMatch, value string) bool {
	if m.Empty() {
		return true
	}

	subject := value
	if !m.CaseSensitive {
		subject = strings.ToLower(subject)
	}

	for _, raw := range m.Values {
		want := strings.TrimSpace(raw)
		if want == "" {
			continue
		}
		if !m.CaseSensitive {
			want = strings.ToLower(want)
		}
		if matchOne(m.Op, subject, want) {
			return true
		}
	}
	return false
}

// matchOne applies a single operator.
//
// An unrecognised operator is treated as equals rather than as "matches
// everything": a typo in a stored rule must not quietly widen it.
func matchOne(op, subject, want string) bool {
	switch op {
	case store.OpContains:
		return strings.Contains(subject, want)
	case store.OpPrefix:
		return strings.HasPrefix(subject, want)
	case store.OpSuffix:
		return strings.HasSuffix(subject, want)
	case store.OpWildcard:
		ok, err := filepath.Match(want, subject)
		return err == nil && ok
	default:
		return subject == want
	}
}

// normalisePath makes two spellings of the same location comparable.
//
// Windows paths arrive from the registry with either separator and in any
// case, so a path rule written with one spelling would silently miss machines
// that reported the other.
func normalisePath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// matches reports whether an application satisfies a rule's criteria.
//
// Populated fields are ANDed; values within a field are ORed.
//
// Empty criteria match NOTHING. This is the most important line here: a rule
// saved from a half-filled form would otherwise match every application on
// every machine, and if its action were block, that is a fleet-wide outage
// authored by a mis-click. Failing closed costs an ineffective rule; failing
// open costs the estate.
func matches(c store.MatchCriteria, app *store.InstalledApp) bool {
	if c.Empty() {
		return false
	}

	if !matchField(c.AppName, app.Name) {
		return false
	}
	if !matchField(c.Publisher, app.Publisher) {
		return false
	}
	if !matchField(c.BundleID, app.BundleID) {
		return false
	}

	if !c.FilePath.Empty() && !matchPath(c.FilePath, app) {
		return false
	}
	if len(c.SHA256) > 0 && !matchHash(c.SHA256, app.SHA256) {
		return false
	}
	return true
}

// matchPath compares against the executable, falling back to the install
// directory.
//
// The executable is what a rule is really about — it is what runs — but plenty
// of records have only a directory, and refusing to match those would make
// path rules silently useless on half the fleet.
func matchPath(m store.StringMatch, app *store.InstalledApp) bool {
	normalised := store.StringMatch{
		Op:            m.Op,
		CaseSensitive: m.CaseSensitive,
		Values:        make([]string, 0, len(m.Values)),
	}
	for _, v := range m.Values {
		normalised.Values = append(normalised.Values, normalisePath(v))
	}

	if app.ExePath != "" && matchField(normalised, normalisePath(app.ExePath)) {
		return true
	}
	return app.InstallPath != "" && matchField(normalised, normalisePath(app.InstallPath))
}

// matchHash compares an application's hash against a rule's list.
//
// An application with no known hash never matches a hash rule. That makes
// hash-rule impact a lower bound rather than a guess, which is the honest
// answer — hashes are collected on demand, not for every application.
func matchHash(wanted []string, actual string) bool {
	if actual == "" {
		return false
	}
	actual = strings.ToLower(strings.TrimSpace(actual))
	for _, w := range wanted {
		if strings.ToLower(strings.TrimSpace(w)) == actual {
			return true
		}
	}
	return false
}
