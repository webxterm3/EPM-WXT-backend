package api

import (
	"github.com/vsay/vsay-agent-backend/internal/store"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// agentBinariesDir is where the deployed agent packages live. Kept in step
// with the same lookup in cmd/server/main.go, which serves downloads from it.
func agentBinariesDir() string {
	if v := strings.TrimSpace(os.Getenv("AGENT_BINARIES_DIR")); v != "" {
		return v
	}
	return "./agent-binaries"
}

// latestAgentVersion returns the version the portal considers "latest".
//
// The VERSION file beside the packages wins, because `make deploy-binaries`
// writes it at the moment it copies them: whatever is offered for download and
// whatever is called "latest" then come from one act, and cannot disagree.
//
// They used to be set separately — packages by a build, "latest" by hand in
// LATEST_AGENT_VERSION — and they drifted, as two hand-synchronised copies of
// a fact always do. The backend was advertising 1.2.1-rc3 while the files on
// disk were 1.0.0-rc3. That is not a cosmetic mismatch: an update is offered
// whenever current != latest, so every agent updated successfully, reported
// the version it had actually installed, still did not match, and was offered
// the same update again for ever. From the portal it looks exactly like an
// update that never applies.
//
// The env var is still honoured, as an override for a deployment that serves
// packages from somewhere this process cannot read.
func latestAgentVersion() string {
	if b, err := os.ReadFile(filepath.Join(agentBinariesDir(), "VERSION")); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v
		}
	}
	if v := strings.TrimSpace(os.Getenv("LATEST_AGENT_VERSION")); v != "" {
		return v
	}
	return "unknown"
}

// backendPublicURL is the externally-reachable base URL agents use to download
// packages (fronted by the vsay-auth gateway). Falls back to BACKEND_URL.
func backendPublicURL() string {
	if v := strings.TrimSpace(os.Getenv("BACKEND_PUBLIC_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(os.Getenv("BACKEND_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8082"
}

// detectOSArch parses the agent's reported os_info string
// ("<platform> <version> <kernelArch>", e.g. "ubuntu 22.04 x86_64") into a
// normalized (osName, arch) pair used to pick the correct package.
func detectOSArch(osInfo string) (osName, arch string) {
	lower := strings.ToLower(osInfo)

	switch {
	case strings.Contains(lower, "debian"), strings.Contains(lower, "ubuntu"), strings.Contains(lower, "kali"), strings.Contains(lower, "mint"):
		osName = "debian"
	case strings.Contains(lower, "rocky"), strings.Contains(lower, "rhel"), strings.Contains(lower, "red hat"), strings.Contains(lower, "centos"), strings.Contains(lower, "fedora"), strings.Contains(lower, "alma"):
		osName = "rhel"
	case strings.Contains(lower, "darwin"), strings.Contains(lower, "mac"):
		osName = "darwin"
	case strings.Contains(lower, "windows"):
		osName = "windows"
	default:
		osName = "linux"
	}

	if strings.Contains(lower, "aarch64") || strings.Contains(lower, "arm64") {
		arch = "arm64"
	} else {
		arch = "amd64"
	}
	return osName, arch
}

// selfUpdatePackage is the file `make deploy-binaries` publishes for one
// platform, or "" where this product has no package.
//
// These names were "vsay-agent-…" until 2026-10-21, a leftover from the fork
// this product was made from, while the Makefile has always deployed
// "wxt-agent-…". Every self-update therefore asked for a file that does not
// exist and died on a 404 — and the comment above this function claimed the
// names matched what the Makefile produced, which is why nobody checked. They
// are pinned against the Makefile by a test now, because nothing else about
// this agrees at compile time.
//
// Linux returns "" rather than a .deb or a tar.gz: EPM targets Windows and
// macOS, the Makefile builds nothing else, and returning a plausible URL for a
// file that was never built is how this bug worked.
func selfUpdatePackage(osName, arch string) string {
	if arch != "arm64" {
		arch = "amd64"
	}
	switch osName {
	case "windows":
		return "wxt-agent-" + arch + ".exe"
	case "darwin":
		return "wxt-agent-" + arch + ".dmg"
	default:
		return ""
	}
}

// selfUpdateURL is where the agent fetches its own replacement, or "" where
// there is nothing to fetch.
func selfUpdateURL(osName, arch string) string {
	pkg := selfUpdatePackage(osName, arch)
	if pkg == "" {
		return ""
	}
	return backendPublicURL() + "/agent/download/" + pkg
}

// agentVersionOf returns the version the machine reported in register metadata.
func agentVersionOf(metadata map[string]string) string {
	if metadata != nil {
		if v := metadata["version"]; v != "" {
			return v
		}
	}
	return "unknown"
}

// CheckAgentUpdate returns the machine's current agent version, the latest available
// version, and whether an update is available.
// GET /api/machines/:agent_id/update-check
func (h *Handler) CheckAgentUpdate(c *gin.Context) {
	agentID := c.Param("agent_id")

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	current := agentVersionOf(machine.Metadata)
	latest := latestAgentVersion()

	// An update is offered when both versions are known and differ.
	updateAvailable := latest != "unknown" && current != "unknown" && current != latest

	c.JSON(http.StatusOK, gin.H{
		"current_version":  current,
		"latest_version":   latest,
		"update_available": updateAvailable,
		"is_connected":     h.agentManager.IsAgentConnected(agentID),
	})
}

// UpdateAgent triggers a self-update on the machine's agent by sending the
// __vsay_update__ command with the package download URL over the gRPC stream.
// POST /api/machines/:agent_id/update
func (h *Handler) UpdateAgent(c *gin.Context) {
	agentID := c.Param("agent_id")

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	if !h.agentManager.IsAgentConnected(agentID) {
		c.JSON(http.StatusConflict, gin.H{"error": "Agent is offline — it must be online to update"})
		return
	}

	osName, arch := detectOSArch(machine.OS)
	downloadURL := selfUpdateURL(osName, arch)
	if downloadURL == "" {
		// Refused here rather than sent as a URL that will 404 on the
		// endpoint. The agent cannot tell a missing package from a broken
		// server, so it reports "download failed" either way — and the
		// portal would show an update that was dispatched successfully.
		c.JSON(http.StatusNotImplemented, gin.H{
			"error": "No agent package is published for " + osName + "/" + arch +
				". This product builds packages for Windows and macOS only.",
		})
		return
	}

	if err := h.agentManager.SendUpdateCommand(agentID, downloadURL); err != nil {
		h.logger.Error("Failed to send update command",
			zap.String("agent_id", agentID),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send update command: " + err.Error()})
		return
	}

	h.logger.Info("Self-update triggered",
		zap.String("agent_id", agentID),
		zap.String("os", osName),
		zap.String("arch", arch),
		zap.String("url", downloadURL))

	// "Who upgraded this machine's agent, and when" — a question that comes up
	// the moment an upgrade coincides with something breaking.
	h.record(c, auditEntry{
		Action: store.AuditAgentUpdated, Resource: "machine",
		ResourceID: agentID, Machine: machine,
		Details: map[string]any{
			"target_os": osName, "target_arch": arch, "package": downloadURL,
		},
	})

	c.JSON(http.StatusOK, gin.H{
		"message":      "Update command sent. The agent will download, update, and restart.",
		"download_url": downloadURL,
		"target_os":    osName,
		"target_arch":  arch,
	})
}
