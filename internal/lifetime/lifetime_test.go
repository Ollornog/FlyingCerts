package lifetime

import (
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestParseAcceptsWhatPeopleWrite(t *testing.T) {
	cases := []struct {
		in        string
		want      time.Duration
		unlimited bool
	}{
		{"1d", Day, false},
		{"30d", 30 * Day, false},
		{"365d", 365 * Day, false},
		{"12h", 12 * time.Hour, false},
		{"1d12h", 36 * time.Hour, false},
		{"90m", 90 * time.Minute, false},
		{"unlimited", 0, true},
		{"Unlimited", 0, true},
		{"  30d  ", 30 * Day, false},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if got.IsUnlimited() != c.unlimited {
			t.Errorf("Parse(%q).IsUnlimited() = %v, want %v", c.in, got.IsUnlimited(), c.unlimited)
		}
		if !c.unlimited && got.Duration() != c.want {
			t.Errorf("Parse(%q) = %v, want %v", c.in, got.Duration(), c.want)
		}
	}
}

// Nothing is guessed at. Each of these could be read two ways, and a
// configuration file that reads two ways is the bug this package exists to
// prevent.
func TestParseRefusesWhatWouldHaveToBeGuessed(t *testing.T) {
	for _, in := range []string{
		"0",     // zero what?
		"0s",    // an explicit zero is not a lifetime
		"-30d",  // negative
		"30",    // days? seconds? nanoseconds?
		"30 d",  // a space where none belongs
		"1h2d",  // days must lead, or it is a typo
		"never", // ambiguous: never expires, or never valid?
		"forever",
		"month",
		"1d2x",
	} {
		if got, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) was accepted as %v", in, got)
		}
	}
}

// The error has to say what to write instead. An error that only says "no"
// sends the reader to the source code.
func TestTheErrorSaysWhatToWriteInstead(t *testing.T) {
	_, err := Parse("30")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"30d", "unlimited"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error for %q does not mention %q: %v", "30", want, err)
		}
	}
}

// Unset, zero and unlimited are three different things, and the type keeps
// them apart. Collapsing any two is how "no expiry" turns into "expires
// immediately" or the other way round.
func TestUnsetZeroAndUnlimitedStayApart(t *testing.T) {
	var unset Span
	if unset.Set() {
		t.Error("the zero Span must be unset")
	}
	if unset.IsUnlimited() {
		t.Error("unset is not unlimited")
	}
	forever := Forever()
	if !forever.Set() || !forever.IsUnlimited() {
		t.Error("Forever must be set and unlimited")
	}
	thirty := Of(30 * Day)
	if thirty.IsUnlimited() {
		t.Error("a duration is not unlimited, however long")
	}
}

// The fallback chain: agent, then broker, then the built-in default.
func TestOrFallsBackOnlyWhenUnset(t *testing.T) {
	var unset Span
	if got := unset.Or(Of(7 * Day)); got.Duration() != 7*Day {
		t.Errorf("unset.Or(7d) = %v", got)
	}
	if got := Of(Day).Or(Of(7 * Day)); got.Duration() != Day {
		t.Errorf("a set value must win: %v", got)
	}
	// Unlimited is a configured value and must not fall back to a duration.
	if got := Forever().Or(Of(7 * Day)); !got.IsUnlimited() {
		t.Error("unlimited fell back to the default")
	}
}

func TestStringRoundTrips(t *testing.T) {
	for _, in := range []string{"1d", "30d", "12h", "unlimited", "1h30m"} {
		parsed, err := Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Parse(parsed.String())
		if err != nil {
			t.Fatalf("Parse(%q.String() = %q): %v", in, parsed.String(), err)
		}
		if again != parsed {
			t.Errorf("%q round-tripped to %q", in, parsed.String())
		}
	}
	var unset Span
	if unset.String() != "default" {
		t.Errorf("unset renders as %q", unset.String())
	}
}

func TestYAML(t *testing.T) {
	var cfg struct {
		A Span `yaml:"a"`
		B Span `yaml:"b"`
		C Span `yaml:"c"`
	}
	if err := yaml.Unmarshal([]byte("a: 30d\nb: unlimited\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.A.Duration() != 30*Day {
		t.Errorf("a = %v", cfg.A)
	}
	if !cfg.B.IsUnlimited() {
		t.Error("b should be unlimited")
	}
	if cfg.C.Set() {
		t.Error("c was not written and must be unset")
	}

	// A bare number is the mistake worth catching: it reads as days to the
	// author and as nanoseconds to a parser.
	var bare struct {
		A Span `yaml:"a"`
	}
	err := yaml.Unmarshal([]byte("a: 30\n"), &bare)
	if err == nil {
		t.Fatal("a bare number was accepted")
	}
	if !strings.Contains(err.Error(), "30d") {
		t.Errorf("the error does not say what to write instead: %v", err)
	}
}
