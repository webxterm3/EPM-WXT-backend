package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Endpoint log collection has MOVED to wxt-log-manager.
//
// What is left here is a door, not the work.
//
// The door cannot move. An agent posts to the host written into its own
// configuration at enrolment, over a connection whose CA it has pinned to
// this backend — so pointing the fleet somewhere else means reconfiguring
// every machine and reissuing trust, which is not a thing to do to make a
// log line appear in a different terminal.
//
// The WORK moved, and that was the point. A fleet shipping system logs
// sends orders of magnitude more bytes than the console API ever does: one
// Mac backfilling is two thousand records every two seconds. Decompressing,
// validating and uploading all of that in the same process as remote
// sessions and policy delivery meant a burst of logging competing with the
// thing somebody is looking at.
//
// So this streams the body through, unread. It does not decompress it, does
// not parse it, does not talk to object storage, and holds none of it in
// memory — a reverse proxy copies as it goes.

// LogForwarder passes agent log batches to wxt-log-manager.
type LogForwarder struct {
	proxy  *httputil.ReverseProxy
	target string
	logger *zap.Logger

	// lastWarned rate-limits the unconfigured notice. Not guarded: a
	// duplicate warning a minute apart is cheaper than a mutex on the
	// path every agent in the fleet takes.
	lastWarned time.Time
}

// NewLogForwarder builds the pass-through. A blank URL means the log
// manager is not deployed, and Ingest then says so rather than pretending.
func NewLogForwarder(logManagerURL string, logger *zap.Logger) (*LogForwarder, error) {
	if strings.TrimSpace(logManagerURL) == "" {
		return &LogForwarder{logger: logger}, nil
	}

	u, err := url.Parse(strings.TrimSuffix(logManagerURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("WXT_LOG_MANAGER_URL is not a URL: %w", err)
	}

	// No stack traces from this path.
	//
	// The backend's logger runs in zap's development mode, which attaches
	// one from WARN upwards. That is useful for a bug in our own code and
	// useless for a network error — the trace is always the same four
	// frames of net/http, printed once per agent per retry, and it buries
	// the one line that says what actually happened.
	quiet := logger.WithOptions(zap.AddStacktrace(zapcore.FatalLevel))

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u)
			// The agent's own Authorization header travels unchanged: the
			// log manager authenticates the machine itself, from the same
			// registration token, rather than trusting this hop.
			r.Out.Host = u.Host
		},
		// A generous but finite copy window. A batch is a few hundred
		// kilobytes; anything taking minutes is a stall, and holding the
		// agent's connection open through it just delays its retry.
		Transport: &http.Transport{ResponseHeaderTimeout: 2 * time.Minute},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// The agent hanging up is NOT a fault, and must not be logged
			// as one.
			//
			// It is the ordinary shape of a client timeout: the agent gives
			// its upload fifteen seconds, and on a slow link or a cold
			// archive the round trip takes longer. The agent then keeps the
			// batch and retries — which is exactly right — but this end saw
			// a cancelled context and used to report it as "could not reach
			// wxt-log-manager", at WARN, with a stack trace. That is a
			// page of noise for a working retry, and it points at the wrong
			// service.
			//
			// There is also nothing to write: the connection is gone.
			if errors.Is(err, context.Canceled) || errors.Is(r.Context().Err(), context.Canceled) {
				quiet.Debug("Log ingest: the agent closed the connection before "+
					"the batch finished; it will retry",
					zap.String("machine_addr", r.RemoteAddr))
				return
			}

			quiet.Warn("Log ingest: could not reach wxt-log-manager", zap.Error(err))
			// 503, so the agent KEEPS the batch and tries again. A 4xx
			// would have it drop logs because a service of ours was down.
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":"log manager unavailable"}`)
		},
	}

	return &LogForwarder{proxy: proxy, target: u.String(), logger: logger}, nil
}

// Ingest handles POST /agent/logs.
func (f *LogForwarder) Ingest(c *gin.Context) {
	if f.proxy == nil {
		// Said once per minute at most: every agent in the fleet arrives
		// here, and one line each would be the flood this move was for.
		f.warnNotConfigured()
		// 503 and not 200: an agent told "accepted" would advance its
		// bookmark and those records would be gone. Keeping the batch is
		// the only answer that loses nothing.
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "log collection is not configured — set WXT_LOG_MANAGER_URL " +
				"on this backend to point at wxt-log-manager",
		})
		return
	}
	f.proxy.ServeHTTP(c.Writer, c.Request)
}

// warnNotConfigured rate-limits the "nowhere to send this" notice.
func (f *LogForwarder) warnNotConfigured() {
	now := time.Now()
	if now.Sub(f.lastWarned) < time.Minute {
		return
	}
	f.lastWarned = now
	f.logger.Warn("Log ingest: agents are shipping logs and there is nowhere to put them",
		zap.String("remedy", "set WXT_LOG_MANAGER_URL on this backend"))
}
