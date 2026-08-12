package handlers

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yix/wg-busy/internal/config"
	"github.com/yix/wg-busy/internal/models"
)

func TestRenderApplyWarningKeepsPersistedMutationOnSuccessPath(t *testing.T) {
	recorder := httptest.NewRecorder()
	err := &config.ApplyError{Err: errors.New("wg syncconf failed")}
	if !renderApplyWarning(recorder, err) {
		t.Fatal("ApplyError was not recognized")
	}
	if recorder.Code != 200 {
		t.Fatalf("status = %d, want 200 so htmx renders the persisted state", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "configuration saved but live apply failed") || !strings.Contains(body, `hx-swap-oob="beforeend:#toast-container"`) {
		t.Fatalf("warning response does not distinguish persistence from apply failure: %s", body)
	}
	if renderApplyWarning(httptest.NewRecorder(), errors.New("not persisted")) {
		t.Fatal("ordinary error was treated as a persisted mutation")
	}
}

func TestNewDualRolePeerGetsDistinctRoutingTables(t *testing.T) {
	peer := models.Peer{IsExitNode: true, PolicyRoutes: []string{"10.5.5.0/24 via 10.0.0.2"}}
	assignNewPeerRoutingTables(&peer, nil)
	if peer.RoutingTableID == 0 || peer.PolicyRoutingTableID == 0 {
		t.Fatalf("table IDs = exit %d, policy %d", peer.RoutingTableID, peer.PolicyRoutingTableID)
	}
	if peer.RoutingTableID == peer.PolicyRoutingTableID {
		t.Fatalf("dual-role peer reused table %d", peer.RoutingTableID)
	}
}
