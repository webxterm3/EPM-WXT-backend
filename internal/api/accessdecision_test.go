package api

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"

	"github.com/vsay/vsay-agent-backend/internal/approvers"
	"github.com/vsay/vsay-agent-backend/internal/store"
)

// decider builds a request context for somebody trying to approve, reject or
// revoke. The approvers service is left unconfigured, so the group-admin
// branch resolves to nobody — every case here is about the checks that come
// before it.
func decider(userID, role, tenantID string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest("POST", "/", nil)
	c.Set("user_id", userID)
	c.Set("role", role)
	c.Set("tenant_id", tenantID)
	return c, rec
}

func handlerForDecisions() *Handler {
	return &Handler{approvers: approvers.New(), logger: zap.NewNop()}
}

// Nobody decides their own request. This is the first requirement of any
// approval workflow and the reason one exists at all, and nothing enforced it:
// a company_admin could ask for access to a machine and grant it to
// themselves, in one round trip.
func TestNobodyApprovesTheirOwnRequest(t *testing.T) {
	const me = "507f1f77bcf86cd799439011"

	for _, role := range []string{"user", "company_admin", "super_admin"} {
		t.Run(role, func(t *testing.T) {
			c, rec := decider(me, role, "t1")
			ar := &store.AccessRequest{RequesterID: me}
			machine := &store.Machine{TenantID: "t1", OwnerID: primitive.NewObjectID()}

			if handlerForDecisions().mayDecide(c, ar, machine) {
				t.Fatalf("a %s approved their own request", role)
			}
			if rec.Code != 403 {
				t.Errorf("refused with %d, want 403", rec.Code)
			}
		})
	}
}

// Even owning the machine does not let you approve your own request. The
// owner path is checked after the self-approval block for exactly this
// reason — somebody who owns a machine and wants timed access to it still has
// to be granted it by another person, or the record means nothing.
func TestOwningTheMachineDoesNotLetYouApproveYourself(t *testing.T) {
	owner := primitive.NewObjectID()
	c, _ := decider(owner.Hex(), "user", "t1")

	ar := &store.AccessRequest{RequesterID: owner.Hex()}
	machine := &store.Machine{TenantID: "t1", OwnerID: owner}

	if handlerForDecisions().mayDecide(c, ar, machine) {
		t.Error("the machine's owner approved their own access request")
	}
}

// The check was "owns the machine, or is an admin" — and "is an admin" was
// read off a header with no reference to WHICH organisation. Creation checked
// the tenant; deciding did not, so a company_admin holding another tenant's
// request id could approve it.
func TestACompanyAdminCannotDecideForAnotherOrganisation(t *testing.T) {
	c, rec := decider(primitive.NewObjectID().Hex(), "company_admin", "tenant-a")

	ar := &store.AccessRequest{RequesterID: primitive.NewObjectID().Hex()}
	machine := &store.Machine{TenantID: "tenant-b", OwnerID: primitive.NewObjectID()}

	if handlerForDecisions().mayDecide(c, ar, machine) {
		t.Fatal("an administrator of one organisation decided a request in another")
	}
	if rec.Code != 403 {
		t.Errorf("refused with %d, want 403", rec.Code)
	}
}

// A super_admin operates across organisations by definition, so the tenant
// check does not apply to them — but the self-approval block still does, and
// that distinction is the whole point of having two separate checks.
func TestASuperAdminCrossesTenantsButNotSelfApproval(t *testing.T) {
	me := primitive.NewObjectID().Hex()
	h := handlerForDecisions()

	t.Run("another person's request in another tenant", func(t *testing.T) {
		c, _ := decider(me, "super_admin", "tenant-a")
		ar := &store.AccessRequest{RequesterID: primitive.NewObjectID().Hex()}
		machine := &store.Machine{TenantID: "tenant-b", OwnerID: primitive.NewObjectID()}

		if !h.mayDecide(c, ar, machine) {
			t.Error("a super_admin was refused a request in another organisation")
		}
	})

	t.Run("their own request", func(t *testing.T) {
		c, _ := decider(me, "super_admin", "tenant-a")
		ar := &store.AccessRequest{RequesterID: me}
		machine := &store.Machine{TenantID: "tenant-a", OwnerID: primitive.NewObjectID()}

		if h.mayDecide(c, ar, machine) {
			t.Error("a super_admin approved their own request")
		}
	})
}

func TestTheMachineOwnerAndTheCompanyAdminMayDecide(t *testing.T) {
	h := handlerForDecisions()
	owner := primitive.NewObjectID()
	someoneElse := primitive.NewObjectID().Hex()

	t.Run("the machine's owner", func(t *testing.T) {
		c, _ := decider(owner.Hex(), "user", "t1")
		ar := &store.AccessRequest{RequesterID: someoneElse}
		machine := &store.Machine{TenantID: "t1", OwnerID: owner}
		if !h.mayDecide(c, ar, machine) {
			t.Error("the machine's owner was refused")
		}
	})

	t.Run("an administrator of the same organisation", func(t *testing.T) {
		c, _ := decider(primitive.NewObjectID().Hex(), "company_admin", "t1")
		ar := &store.AccessRequest{RequesterID: someoneElse}
		machine := &store.Machine{TenantID: "t1", OwnerID: owner}
		if !h.mayDecide(c, ar, machine) {
			t.Error("an administrator of the same organisation was refused")
		}
	})
}

// An ordinary user with no relationship to the machine decides nothing.
func TestAnUnrelatedUserDecidesNothing(t *testing.T) {
	c, rec := decider(primitive.NewObjectID().Hex(), "user", "t1")
	ar := &store.AccessRequest{RequesterID: primitive.NewObjectID().Hex()}
	machine := &store.Machine{TenantID: "t1", OwnerID: primitive.NewObjectID()}

	if handlerForDecisions().mayDecide(c, ar, machine) {
		t.Fatal("somebody with no relationship to the machine decided a request for it")
	}
	if rec.Code != 403 {
		t.Errorf("refused with %d, want 403", rec.Code)
	}
}

// A request with no recorded requester must not accidentally match an empty
// user id and block every approval — nor should an empty caller id match it.
func TestAnEmptyIdentityNeverMatches(t *testing.T) {
	h := handlerForDecisions()
	owner := primitive.NewObjectID()

	c, _ := decider("", "user", "t1")
	ar := &store.AccessRequest{RequesterID: ""}
	machine := &store.Machine{TenantID: "t1", OwnerID: owner}

	// Refused because they are nobody, not because empty equals empty.
	if h.mayDecide(c, ar, machine) {
		t.Error("an unidentified caller decided a request")
	}

	c2, _ := decider(owner.Hex(), "user", "t1")
	ar2 := &store.AccessRequest{RequesterID: ""}
	if !h.mayDecide(c2, ar2, machine) {
		t.Error("an old request with no recorded requester blocked its own machine's owner")
	}
}
