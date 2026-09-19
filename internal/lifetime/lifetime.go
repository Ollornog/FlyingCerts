// Package lifetime parses how long something stays valid.
//
// It exists because Go's own duration syntax stops at hours, and certificate
// lifetimes are spoken about in days. Writing 30 days as "720h" is not wrong,
// it is merely unreadable — and a configuration value nobody can read at a
// glance is a configuration value that ends up wrong.
//
// It also carries the one case a duration cannot express: an identity that
// does not expire. That is deliberately a separate state rather than a very
// large number, so every place that has to think about it is forced to.
package lifetime

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Day is what this package adds to Go's units.
const Day = 24 * time.Hour

// Unlimited is the word that means "does not expire".
//
// One spelling, not three. "never" would be ambiguous — never expires, or
// never valid? — and a configuration file is not the place for a word that
// reads both ways.
const Unlimited = "unlimited"

// Span is a configured lifetime: a duration, "unlimited", or unset.
//
// The zero value is unset, which means "use the default". That is why this is
// a struct and not a time.Duration: zero has to be distinguishable from an
// explicit zero, and "unlimited" has to be distinguishable from "very long".
type Span struct {
	d         time.Duration
	unlimited bool
	set       bool
}

// Of returns a Span for a duration.
func Of(d time.Duration) Span { return Span{d: d, set: true} }

// Forever returns the unlimited Span.
func Forever() Span { return Span{unlimited: true, set: true} }

// Set reports whether a value was configured at all.
func (s Span) Set() bool { return s.set }

// IsUnlimited reports whether this lifetime does not expire.
func (s Span) IsUnlimited() bool { return s.unlimited }

// Duration is the configured duration. It is zero for an unset Span and
// meaningless for an unlimited one — check IsUnlimited first.
func (s Span) Duration() time.Duration { return s.d }

// Or returns s when it is set, and the fallback otherwise. This is how the
// per-agent value falls back to the broker-wide one, and that to the default.
func (s Span) Or(fallback Span) Span {
	if s.set {
		return s
	}
	return fallback
}

// String renders the span the way it would be written in a configuration file.
func (s Span) String() string {
	switch {
	case !s.set:
		return "default"
	case s.unlimited:
		return Unlimited
	case s.d%Day == 0 && s.d >= Day:
		return strconv.FormatInt(int64(s.d/Day), 10) + "d"
	default:
		return s.d.String()
	}
}

// Parse reads a lifetime: "30d", "12h", "1d12h" or "unlimited".
func Parse(text string) (Span, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Span{}, nil
	}
	if strings.EqualFold(text, Unlimited) {
		return Forever(), nil
	}

	d, err := parseWithDays(text)
	if err != nil {
		return Span{}, fmt.Errorf("%q is not a lifetime: write it like 30d, 12h, 1d12h or %s (%w)",
			text, Unlimited, err)
	}
	if d < 0 {
		return Span{}, fmt.Errorf("%q is negative", text)
	}
	if d == 0 {
		// Zero would silently mean "use the default", which is not what
		// somebody writing 0 has in mind. Say so instead of guessing.
		return Span{}, fmt.Errorf("a lifetime of %q is not a lifetime: leave the setting out "+
			"to use the default, or write %s", text, Unlimited)
	}
	return Of(d), nil
}

// parseWithDays handles a leading day count and hands the rest to the standard
// library, so "1d12h" works and every unit Go knows keeps working.
func parseWithDays(text string) (time.Duration, error) {
	neg := strings.HasPrefix(text, "-")
	body := strings.TrimPrefix(strings.TrimPrefix(text, "-"), "+")

	i := strings.IndexByte(body, 'd')
	if i < 0 {
		return time.ParseDuration(text)
	}
	// Only a leading "<digits>d" counts. Anything else ("1h2d") is a typo
	// worth reporting rather than a syntax worth supporting.
	days, err := strconv.ParseInt(body[:i], 10, 32)
	if err != nil {
		return 0, errors.New("the day count must be a whole number")
	}
	total := time.Duration(days) * Day
	if rest := body[i+1:]; rest != "" {
		r, err := time.ParseDuration(rest)
		if err != nil {
			return 0, err
		}
		total += r
	}
	if neg {
		total = -total
	}
	return total, nil
}

// UnmarshalYAML lets a Span be written directly in a configuration file.
//
// This is yaml.v3's own interface, taking a node rather than the older
// decode-callback form. Both work, but only this one makes the type visible
// as a leaf to anything that walks the configuration by reflection — and one
// such walk is what keeps the backup scope honest.
func (s *Span) UnmarshalYAML(node *yaml.Node) error {
	// A bare number is the likely mistake: "identity_lifetime: 30" reads as
	// days to the person writing it and as nanoseconds to a parser. Checking
	// the tag refuses it before either reading can happen.
	if node.Tag != "!!str" {
		return fmt.Errorf("line %d: a lifetime needs a unit — write 30d, 12h or %s",
			node.Line, Unlimited)
	}
	parsed, err := Parse(node.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}
	*s = parsed
	return nil
}

// MarshalYAML writes it back the way it was meant.
func (s Span) MarshalYAML() (any, error) {
	if !s.set {
		return nil, nil
	}
	return s.String(), nil
}
