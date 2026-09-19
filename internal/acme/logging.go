package acme

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// MinRedactableSecretLength is the shortest value worth redacting.
//
// Redacting very short strings would do more harm than good: a two-character
// "secret" would match inside ordinary words and turn the log into confetti,
// which hides more than it protects. Anything genuinely secret is longer.
const MinRedactableSecretLength = 6

// redactedMarker replaces anything withheld, and is deliberately visible: a
// reader should see that something was removed rather than wonder why a line
// reads oddly.
const redactedMarker = "[redacted]"

// sensitiveKeys are attribute names whose value is withheld regardless of what
// it contains. This catches secrets we were never told about.
var sensitiveKeys = []string{
	"token", "secret", "password", "passwd", "credential", "apikey", "api_key",
	"auth", "key", "bearer", "signature", "session",
}

// Redactor wraps a slog.Handler and removes known secrets from everything that
// passes through it.
//
// Why this exists: Cert Warden leaked its DNS provider credentials in plain
// text to the journal, and not through its own code — the embedded ACME library
// logged them (certwarden#144). A library cannot know which of its values are
// sensitive in our deployment, so the filter belongs on our side, between the
// library and anything that writes to disk.
//
// Two mechanisms, deliberately overlapping:
//
//   - by value: every known secret is replaced wherever it appears, including
//     in the middle of a free-form message. This is the one that would have
//     caught certwarden#144, because there the secret appeared in a message
//     nobody had marked as sensitive.
//   - by key: attributes whose name looks sensitive are withheld whole, which
//     catches secrets that were never registered with the redactor.
type Redactor struct {
	handler slog.Handler
	secrets []string
}

// NewRedactor wraps h so that none of secrets can pass through it.
//
// Values shorter than MinRedactableSecretLength are ignored, and so are empty
// ones — an empty secret would otherwise match everywhere.
func NewRedactor(h slog.Handler, secrets ...string) *Redactor {
	kept := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if len(s) >= MinRedactableSecretLength {
			kept = append(kept, s)
		}
	}
	return &Redactor{handler: h, secrets: kept}
}

// Enabled implements slog.Handler.
func (r *Redactor) Enabled(ctx context.Context, level slog.Level) bool {
	return r.handler.Enabled(ctx, level)
}

// Handle implements slog.Handler, redacting the message and every attribute.
func (r *Redactor) Handle(ctx context.Context, rec slog.Record) error {
	clean := slog.NewRecord(rec.Time, rec.Level, r.scrub(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(r.scrubAttr(a))
		return true
	})
	return r.handler.Handle(ctx, clean)
}

// WithAttrs implements slog.Handler.
func (r *Redactor) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = r.scrubAttr(a)
	}
	return &Redactor{handler: r.handler.WithAttrs(scrubbed), secrets: r.secrets}
}

// WithGroup implements slog.Handler.
func (r *Redactor) WithGroup(name string) slog.Handler {
	return &Redactor{handler: r.handler.WithGroup(name), secrets: r.secrets}
}

// scrub replaces every known secret found anywhere in s.
func (r *Redactor) scrub(s string) string {
	for _, secret := range r.secrets {
		if strings.Contains(s, secret) {
			s = strings.ReplaceAll(s, secret, redactedMarker)
		}
	}
	return s
}

// scrubAttr withholds an attribute whose name looks sensitive, and otherwise
// scrubs its value.
func (r *Redactor) scrubAttr(a slog.Attr) slog.Attr {
	if isSensitiveKey(a.Key) {
		return slog.String(a.Key, redactedMarker)
	}
	// Groups are walked so a secret cannot hide one level down.
	if a.Value.Kind() == slog.KindGroup {
		inner := a.Value.Group()
		scrubbed := make([]slog.Attr, len(inner))
		for i, g := range inner {
			scrubbed[i] = r.scrubAttr(g)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(scrubbed...)}
	}
	// Render once and scrub the text: a secret can sit inside a URL, an error
	// or a struct, not only in a plain string attribute.
	rendered := a.Value.Resolve().String()
	if cleaned := r.scrub(rendered); cleaned != rendered {
		return slog.String(a.Key, cleaned)
	}
	return a
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// String makes accidental printing of a Redactor useless rather than revealing.
func (r *Redactor) String() string {
	return fmt.Sprintf("Redactor(%d secrets)", len(r.secrets))
}
