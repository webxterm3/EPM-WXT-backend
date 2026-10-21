package email

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Service is a simple SMTP email sender. All SMTP config is read from env vars at send time
// so the struct itself is stateless and safe to share.
type Service struct{}

// New returns a new email Service.
func New() *Service {
	return &Service{}
}

// stripCRLF removes carriage-return/newline characters so a value can't smuggle
// extra lines into a raw SMTP header block.
func stripCRLF(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return v
}

// Configured reports whether a send would actually reach anybody.
//
// Send already skips silently when SMTP is not set up, which is the right
// behaviour for an optional notification but the wrong thing to be silent
// about: an administrator who switches on alerts and never receives one has no
// way to tell "nothing happened" from "nothing was ever going to be sent".
// Callers use this to say which it is, and the portal shows it.
func (s *Service) Configured() bool {
	if strings.TrimSpace(os.Getenv("AUTH_EMAIL_URL")) != "" {
		return true
	}
	return strings.TrimSpace(os.Getenv("SMTP_USERNAME")) != ""
}

// esc makes a value safe to drop into one of the HTML bodies below.
//
// Every value these templates interpolate is attacker-influenced in some
// degree — a machine name and an access-request note are typed by a user, and
// an application name and path are read off the endpoint from files a local
// user can author. fmt.Sprintf into HTML without this is an injection into
// whatever reads the mail.
func esc(v string) string { return template.HTMLEscapeString(v) }

// Send sends an HTML email. It prefers routing through vsay-auth (so SMTP creds live in
// ONE place): if AUTH_EMAIL_URL is set, it POSTs to vsay-auth's /internal/send-email
// with the shared gateway token. Otherwise it falls back to sending SMTP directly
// (and skips silently if SMTP_USERNAME is unset).
func (s *Service) Send(to, subject, htmlBody string) error {
	// Subject/to/from are interpolated directly into raw header lines below, and
	// subject in particular can carry user-controlled data (e.g. a machine name
	// the user picked). Strip CR/LF so nobody can smuggle extra headers (e.g. a
	// "Bcc:" line) via SMTP header injection.
	to = stripCRLF(to)
	subject = stripCRLF(subject)
	// Preferred path: forward to vsay-auth's SMTP.
	if authURL := os.Getenv("AUTH_EMAIL_URL"); authURL != "" {
		return s.sendViaAuth(authURL, []string{to}, subject, htmlBody)
	}

	host := os.Getenv("SMTP_HOST")
	if host == "" {
		host = "smtp.gmail.com"
	}
	port := os.Getenv("SMTP_PORT")
	if port == "" {
		port = "587"
	}
	username := os.Getenv("SMTP_USERNAME")
	if username == "" {
		log.Printf("email: SMTP_USERNAME not set, skipping email to %s (subject: %s)", to, subject)
		return nil
	}
	password := os.Getenv("SMTP_PASSWORD")
	from := os.Getenv("SMTP_FROM")
	if from == "" {
		from = "noreply@vsay.com"
	}

	auth := smtp.PlainAuth("", username, password, host)

	headers := strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=\"UTF-8\"",
	}, "\r\n")

	body := headers + "\r\n\r\n" + htmlBody

	addr := host + ":" + port
	if err := smtp.SendMail(addr, auth, from, []string{to}, []byte(body)); err != nil { // #nosec G707 -- to/subject are CRLF-stripped above (stripCRLF); gosec's taint tracker doesn't see through the helper
		return fmt.Errorf("email: send failed: %w", err)
	}
	return nil
}

// sendViaAuth POSTs the email to vsay-auth's internal endpoint, which owns the SMTP
// config. Authenticated with the shared gateway secret.
// url is always AUTH_EMAIL_URL, a deployment-time env var — never derived from a
// request — so this is not an attacker-reachable SSRF sink despite the taint warning.
func (s *Service) sendViaAuth(url string, to []string, subject, htmlBody string) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"to":      to,
		"subject": subject,
		"html":    htmlBody,
	})
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload)) // #nosec G704 -- url is AUTH_EMAIL_URL env var, not request-derived
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-Token", os.Getenv("GATEWAY_SECRET"))

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req) // #nosec G704 -- same req built from AUTH_EMAIL_URL above, not request-derived
	if err != nil {
		return fmt.Errorf("email: forward to vsay-auth failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("email: vsay-auth returned %d", resp.StatusCode)
	}
	return nil
}

// SendIntrusionAlert warns that someone logged into the machine directly (SSH/RDP),
// bypassing the vsay portal. Sent to every recipient in `to`.
func (s *Service) SendIntrusionAlert(to []string, machineName, protocol, osUser, sourceIP string, loginAt time.Time) error {
	if len(to) == 0 {
		return nil
	}
	subject := fmt.Sprintf("⚠️ Direct %s login detected on %s", strings.ToUpper(protocol), machineName)
	body := fmt.Sprintf(`
		<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:560px;margin:0 auto">
		  <div style="background:#b91c1c;color:#fff;padding:16px 20px;border-radius:10px 10px 0 0">
		    <h2 style="margin:0;font-size:18px">⚠️ Direct access detected</h2>
		  </div>
		  <div style="border:1px solid #eee;border-top:none;padding:20px;border-radius:0 0 10px 10px;color:#111">
		    <p>Someone connected to <strong>%s</strong> directly over <strong>%s</strong> — outside the vsay portal.</p>
		    <table style="width:100%%;border-collapse:collapse;font-size:14px;margin:12px 0">
		      <tr><td style="padding:6px 0;color:#666">Machine</td><td style="padding:6px 0"><strong>%s</strong></td></tr>
		      <tr><td style="padding:6px 0;color:#666">Protocol</td><td style="padding:6px 0">%s</td></tr>
		      <tr><td style="padding:6px 0;color:#666">Account</td><td style="padding:6px 0">%s</td></tr>
		      <tr><td style="padding:6px 0;color:#666">From IP</td><td style="padding:6px 0">%s</td></tr>
		      <tr><td style="padding:6px 0;color:#666">Time</td><td style="padding:6px 0">%s</td></tr>
		    </table>
		    <p style="color:#666;font-size:13px">If this was you or your team, no action is needed. Otherwise, review the machine's access history in the vsay portal immediately.</p>
		  </div>
		</div>`,
		machineName, strings.ToUpper(protocol), machineName, strings.ToUpper(protocol),
		osUser, sourceIP, loginAt.UTC().Format("2006-01-02 15:04:05 MST"))

	var firstErr error
	for _, addr := range to {
		if addr == "" {
			continue
		}
		if err := s.Send(addr, subject, body); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// SendAccessRequestNotification notifies the machine owner about a new access request.
func (s *Service) SendAccessRequestNotification(ownerEmail, ownerName, requesterName, machineName string, durationHours int, note string) error {
	subject := fmt.Sprintf("New Machine Access Request - %s", machineName)

	noteSection := ""
	if note != "" {
		noteSection = fmt.Sprintf(`<p><strong>Note from requester:</strong><br>%s</p>`, note)
	}

	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
  <h2>New Machine Access Request</h2>
  <p>Hello %s,</p>
  <p><strong>%s</strong> has requested access to your machine <strong>%s</strong>.</p>
  <p><strong>Requested duration:</strong> %d hour(s)</p>
  %s
  <p>Please log in to the VSay portal to approve or reject this request.</p>
  <hr>
  <p style="color:#888;font-size:12px;">This is an automated notification from VSay.</p>
</body>
</html>`, ownerName, requesterName, machineName, durationHours, noteSection)

	return s.Send(ownerEmail, subject, body)
}

// SendAccessRequestDecision notifies the requester of an approval or rejection.
func (s *Service) SendAccessRequestDecision(requesterEmail, requesterName, machineName, status, comment string, expiresAt *time.Time) error {
	statusLabel := "Approved"
	if status == "rejected" {
		statusLabel = "Rejected"
	} else if status == "revoked" {
		statusLabel = "Revoked"
	}

	subject := fmt.Sprintf("Machine Access Request %s - %s", statusLabel, machineName)

	var extraSection string
	if status == "approved" && expiresAt != nil {
		extraSection = fmt.Sprintf(`<p><strong>Access expires at:</strong> %s</p>`, expiresAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if status == "rejected" && comment != "" {
		extraSection = fmt.Sprintf(`<p><strong>Reason:</strong><br>%s</p>`, comment)
	}

	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
  <h2>Machine Access Request %s</h2>
  <p>Hello %s,</p>
  <p>Your access request for machine <strong>%s</strong> has been <strong>%s</strong>.</p>
  %s
  <p>Please log in to the VSay portal for more details.</p>
  <hr>
  <p style="color:#888;font-size:12px;">This is an automated notification from VSay.</p>
</body>
</html>`, statusLabel, requesterName, machineName, strings.ToLower(statusLabel), extraSection)

	return s.Send(requesterEmail, subject, body)
}

// fanOut sends one message to every recipient, and reports the first failure
// without letting it stop the rest. One bad address must not silence everybody
// else on an alert.
func (s *Service) fanOut(to []string, subject, body string) error {
	var firstErr error
	for _, addr := range to {
		if strings.TrimSpace(addr) == "" {
			continue
		}
		if err := s.Send(addr, subject, body); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// shell wraps a body in the common frame. accent colours the header bar.
func shell(accent, heading, inner string) string {
	return fmt.Sprintf(`
		<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:560px;margin:0 auto">
		  <div style="background:%s;color:#fff;padding:16px 20px;border-radius:10px 10px 0 0">
		    <h2 style="margin:0;font-size:18px">%s</h2>
		  </div>
		  <div style="border:1px solid #eee;border-top:none;padding:20px;border-radius:0 0 10px 10px;color:#111">
		    %s
		  </div>
		</div>`, accent, heading, inner)
}

// row is one line of the little fact table these messages share.
func row(label, value string) string {
	return fmt.Sprintf(
		`<tr><td style="padding:6px 0;color:#666;white-space:nowrap">%s</td><td style="padding:6px 0 6px 16px"><strong>%s</strong></td></tr>`,
		esc(label), esc(value))
}

func table(rows ...string) string {
	return `<table style="width:100%;border-collapse:collapse;font-size:14px;margin:12px 0">` +
		strings.Join(rows, "") + `</table>`
}

// SendElevationAlert reports that an application ran with administrator rights
// because a policy said it could.
//
// This is the one notification in the product that reports a privilege being
// GIVEN rather than taken away. Everything else application control does makes
// a machine more restricted, and the worst case of getting it wrong is software
// that will not start; this one hands out administrator rights, so it is mailed
// as it happens rather than left to be found in a report nobody opens.
func (s *Service) SendElevationAlert(to []string, machineName, appName, path, rule, policy, osUser string, at time.Time) error {
	if len(to) == 0 {
		return nil
	}
	subject := fmt.Sprintf("%s ran with administrator rights on %s", appName, machineName)

	rows := []string{
		row("Machine", machineName),
		row("Application", appName),
	}
	if path != "" {
		rows = append(rows, row("Path", path))
	}
	if osUser != "" {
		rows = append(rows, row("Account", osUser))
	}
	rows = append(rows,
		row("Rule", rule),
		row("Policy", policy),
		row("Time", at.UTC().Format("2006-01-02 15:04:05 MST")),
	)

	inner := fmt.Sprintf(
		`<p><strong>%s</strong> was started with administrator rights on <strong>%s</strong>, because a policy rule allows it.</p>%s`+
			`<p style="color:#666;font-size:13px">This is expected if somebody wrote that rule on purpose. If it is not expected, `+
			`remove or disable the rule in the portal — the grant is withdrawn on the next policy change.</p>`,
		esc(appName), esc(machineName), table(rows...))

	return s.fanOut(to, subject, shell("#b45309", "Administrator rights granted", inner))
}

// SendElevationUnavailable reports that a rule asking for elevation cannot be
// honoured on the machine it reached.
//
// Worth a mail of its own, and not folded into a generic failure, because the
// administrator who wrote that rule believes software is running elevated and
// it is not. A rule that looks configured and does nothing is the failure this
// product has shipped twice; this is the thing that stops the third time being
// discovered months later.
func (s *Service) SendElevationUnavailable(to []string, machineName, appName, rule, policy, reason string) error {
	if len(to) == 0 {
		return nil
	}
	subject := fmt.Sprintf("Elevation rule is not being honoured on %s", machineName)

	inner := fmt.Sprintf(
		`<p>A policy rule asks for <strong>%s</strong> to run with administrator rights on <strong>%s</strong>, `+
			`but that machine cannot do it. <strong>Nothing is running elevated because of this rule.</strong></p>%s`+
			`<p style="color:#666;font-size:13px">The rule is saved and will apply if the machine gains the ability. `+
			`Until then, use a Block or Allow rule for anything you need enforced today.</p>`,
		esc(appName), esc(machineName),
		table(
			row("Machine", machineName),
			row("Application", appName),
			row("Rule", rule),
			row("Policy", policy),
			row("Reason", reason),
		))

	return s.fanOut(to, subject, shell("#b45309", "Rule cannot be honoured", inner))
}

// SendRemoteSessionAlert reports that somebody opened a remote session on a
// machine.
//
// Sent to everyone who uses the machine, not only whoever authorised it: the
// person whose desktop is being watched is the one who most needs to know, and
// they are not in the approval loop.
func (s *Service) SendRemoteSessionAlert(to []string, machineName, operator, kind, sourceIP string, at time.Time) error {
	if len(to) == 0 {
		return nil
	}
	subject := fmt.Sprintf("Remote session started on %s", machineName)

	rows := []string{
		row("Machine", machineName),
		row("Started by", operator),
		row("Type", kind),
	}
	if sourceIP != "" {
		rows = append(rows, row("From IP", sourceIP))
	}
	rows = append(rows, row("Time", at.UTC().Format("2006-01-02 15:04:05 MST")))

	inner := fmt.Sprintf(
		`<p><strong>%s</strong> started a remote session on <strong>%s</strong>.</p>%s`+
			`<p style="color:#666;font-size:13px">Every remote session is recorded. If this was not expected, `+
			`review the machine's session history in the portal.</p>`,
		esc(operator), esc(machineName), table(rows...))

	return s.fanOut(to, subject, shell("#1d4ed8", "Remote session started", inner))
}

// SendElevationRefused reports that something tried to start with
// administrator rights and was turned down.
//
// Deliberately NOT folded into SendElevationUnavailable, although both are a
// failed elevate event. They are opposite facts:
//
//	unavailable — the machine cannot honour a rule somebody wrote. A
//	              configuration problem, and the administrator's own doing.
//	refused     — a launch asked for administrator rights and policy said no.
//	              Somebody on that machine tried something they are not
//	              allowed, possibly repeatedly.
//
// Mailing the second as the first tells an administrator their configuration
// is broken at the exact moment somebody is probing it, and sends them to fix
// a rule that is working correctly.
func (s *Service) SendElevationRefused(to []string, machineName, appName, path, osUser, reason string, at time.Time) error {
	if len(to) == 0 {
		return nil
	}
	subject := fmt.Sprintf("Elevation refused on %s", machineName)

	rows := []string{row("Machine", machineName), row("Application", appName)}
	if path != "" {
		rows = append(rows, row("Path", path))
	}
	if osUser != "" {
		rows = append(rows, row("Account", osUser))
	}
	rows = append(rows,
		row("Reason", reason),
		row("Time", at.UTC().Format("2006-01-02 15:04:05 MST")),
	)

	inner := fmt.Sprintf(
		`<p>Something tried to start <strong>%s</strong> with administrator rights on `+
			`<strong>%s</strong>, and policy refused it. <strong>No privilege was granted.</strong></p>%s`+
			`<p style="color:#666;font-size:13px">Nothing is broken — this is application control working. `+
			`Repeated refusals for the same application are worth looking into.</p>`,
		esc(appName), esc(machineName), table(rows...))

	return s.fanOut(to, subject, shell("#b91c1c", "Elevation refused", inner))
}
