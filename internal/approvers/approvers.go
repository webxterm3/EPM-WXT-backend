// Package approvers answers "who decides access requests for this machine".
//
// The answer lives in vsay-auth, which owns groups and their administrators.
// This backend holds Machine.GroupIDs, denormalised from there, so it knows
// WHICH groups a machine is in but not who administers them.
//
// Asked rather than mirrored. The obvious alternative is to push the approver
// list across alongside the group ids, and it is the wrong one: an approver
// list that has drifted routes a request to somebody who no longer decides, or
// to nobody at all, and neither looks wrong until an approval is waited on and
// never arrives. Requests are made a handful of times a day, so one call is
// cheap and always right.
package approvers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Approver is one person who may decide requests for a machine.
type Approver struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	// GroupID is which group makes them an approver, for the audit trail:
	// "approved by X, who administers Finance" is a different fact from
	// "approved by X, an administrator of everything".
	GroupID string `json:"group_id"`
}

// Service resolves approvers over vsay-auth's internal endpoint.
type Service struct {
	baseURL string
	secret  string
	client  *http.Client
}

// New reads the deployment's configuration.
//
// Absent configuration is not an error. Where vsay-auth cannot be reached,
// every lookup returns nobody and the caller falls back to whoever administers
// the organisation — which is what happened before group administrators
// existed. A deployment that has not been told where vsay-auth is keeps
// working exactly as it did.
func New() *Service {
	return &Service{
		baseURL: strings.TrimRight(strings.TrimSpace(os.Getenv("AUTH_INTERNAL_URL")), "/"),
		secret:  os.Getenv("GATEWAY_SECRET"),
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Configured reports whether a lookup would reach anything.
//
// Callers use it to tell "this machine's groups have no administrators" from
// "nobody asked", which are different facts and send somebody to different
// places.
func (s *Service) Configured() bool { return s.baseURL != "" }

// ForGroups returns the people who administer any of these groups.
//
// Deduplicated across groups by vsay-auth, so a machine in two groups one
// person administers yields that person once.
func (s *Service) ForGroups(ctx context.Context, groupIDs []string) ([]Approver, error) {
	if !s.Configured() || len(groupIDs) == 0 {
		return nil, nil
	}

	payload, err := json.Marshal(map[string][]string{"group_ids": groupIDs})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.baseURL+"/internal/group-approvers", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-Token", s.secret)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("asking vsay-auth who administers these groups: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vsay-auth answered %d", resp.StatusCode)
	}

	var out struct {
		Approvers []Approver `json:"approvers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Approvers, nil
}

// Includes reports whether userID is among these approvers.
//
// Compared on the user id, never the username or the email: both are
// changeable, and an authorization check that turns on a display name is one
// rename away from being wrong.
func Includes(list []Approver, userID string) bool {
	if userID == "" {
		return false
	}
	for _, a := range list {
		if a.UserID == userID {
			return true
		}
	}
	return false
}

// Emails returns the addresses to notify.
func Emails(list []Approver) []string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		if strings.TrimSpace(a.Email) != "" {
			out = append(out, a.Email)
		}
	}
	return out
}
