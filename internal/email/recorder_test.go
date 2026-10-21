package email

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// recorder stands in for vsay-auth's /internal/send-email, so a test can read
// the HTML a template produced without an SMTP server anywhere near it.
type recorder struct {
	srv  *httptest.Server
	mu   sync.Mutex
	body string
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		var payload struct {
			HTML string `json:"html"`
		}
		_ = json.Unmarshal(raw, &payload)
		r.mu.Lock()
		r.body = payload.HTML
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) URL() string { return r.srv.URL }

func (r *recorder) Body() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body
}
