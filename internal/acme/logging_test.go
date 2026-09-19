package acme

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// logged runs fn against a Redactor and returns everything that was written.
func logged(secrets []string, fn func(*slog.Logger)) string {
	var buf bytes.Buffer
	base := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	fn(slog.New(NewRedactor(base, secrets...)))
	return buf.String()
}

// The exact shape of certwarden#144: the credential appears inside a free-form
// message that nobody marked as sensitive.
func TestSecretInAPlainMessageIsRemoved(t *testing.T) {
	const token = "dns-provider-token-abc123"
	out := logged([]string{token}, func(l *slog.Logger) {
		l.Info("calling provider API with credentials " + token + " for zone example.com")
	})

	if strings.Contains(out, token) {
		t.Errorf("the secret survived in the message:\n%s", out)
	}
	if !strings.Contains(out, redactedMarker) {
		t.Errorf("nothing marks the removal:\n%s", out)
	}
	// The surrounding context must survive — a log that hides everything is
	// as useless as one that hides nothing.
	if !strings.Contains(out, "example.com") {
		t.Errorf("harmless context was removed too:\n%s", out)
	}
}

func TestSecretInAnAttributeValueIsRemoved(t *testing.T) {
	const secret = "s3cret-value-long-enough"
	out := logged([]string{secret}, func(l *slog.Logger) {
		l.Info("request failed", slog.String("url", "https://api.example.com/?auth="+secret))
	})
	if strings.Contains(out, secret) {
		t.Errorf("the secret survived inside a URL:\n%s", out)
	}
}

func TestSecretInsideAnErrorIsRemoved(t *testing.T) {
	const secret = "another-long-secret-1"
	err := errors.New("authentication with " + secret + " was rejected")
	out := logged([]string{secret}, func(l *slog.Logger) {
		l.Error("provider error", slog.Any("err", err))
	})
	if strings.Contains(out, secret) {
		t.Errorf("the secret survived inside an error:\n%s", out)
	}
}

func TestSecretInAGroupIsRemoved(t *testing.T) {
	const secret = "grouped-secret-value"
	out := logged([]string{secret}, func(l *slog.Logger) {
		l.Info("config", slog.Group("provider",
			slog.String("name", "example"),
			slog.String("endpoint", "https://api.example.com/"+secret)))
	})
	if strings.Contains(out, secret) {
		t.Errorf("the secret survived one level down in a group:\n%s", out)
	}
	if !strings.Contains(out, "example") {
		t.Errorf("the group lost its harmless contents:\n%s", out)
	}
}

// Even a secret the redactor was never told about must not pass, when the
// attribute name gives it away.
func TestSensitiveKeyIsWithheldEvenIfUnknown(t *testing.T) {
	out := logged(nil, func(l *slog.Logger) {
		l.Info("configured",
			slog.String("api_token", "never-registered-with-us"),
			slog.String("zone", "example.com"))
	})
	if strings.Contains(out, "never-registered-with-us") {
		t.Errorf("an unknown secret passed under a sensitive key:\n%s", out)
	}
	if !strings.Contains(out, "example.com") {
		t.Errorf("the harmless attribute was dropped:\n%s", out)
	}
}

func TestWithAttrsAndWithGroupKeepRedacting(t *testing.T) {
	const secret = "persistent-secret-xyz"

	// slog.With and WithGroup return new handlers — the redaction must survive
	// that, otherwise a logger derived once leaks from then on.
	out := logged([]string{secret}, func(l *slog.Logger) {
		l.With(slog.String("component", "dns")).
			WithGroup("call").
			Info("sending " + secret)
	})
	if strings.Contains(out, secret) {
		t.Errorf("the secret survived a derived logger:\n%s", out)
	}

	out = logged([]string{secret}, func(l *slog.Logger) {
		l.With(slog.String("endpoint", "https://x.example.com/"+secret)).Info("ready")
	})
	if strings.Contains(out, secret) {
		t.Errorf("the secret survived in an attribute bound via With:\n%s", out)
	}
}

// Short strings are left alone on purpose: redacting them would match inside
// ordinary words and destroy the log without protecting anything.
func TestVeryShortSecretsAreIgnored(t *testing.T) {
	out := logged([]string{"ab", ""}, func(l *slog.Logger) {
		l.Info("about to fabricate a table")
	})
	if strings.Contains(out, redactedMarker) {
		t.Errorf("a two-character secret shredded the message:\n%s", out)
	}
	if !strings.Contains(out, "fabricate") {
		t.Errorf("the message did not survive:\n%s", out)
	}
}

func TestSeveralSecretsAtOnce(t *testing.T) {
	secrets := []string{"first-secret-value", "second-secret-value"}
	out := logged(secrets, func(l *slog.Logger) {
		l.Info("using first-secret-value and second-secret-value together")
	})
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("secret %q survived:\n%s", s, out)
		}
	}
}

func TestRedactorDoesNotRevealItselfWhenPrinted(t *testing.T) {
	r := NewRedactor(slog.NewTextHandler(&bytes.Buffer{}, nil), "a-secret-value-here")
	if strings.Contains(r.String(), "a-secret-value-here") {
		t.Errorf("printing the redactor revealed a secret: %s", r.String())
	}
}
