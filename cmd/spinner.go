package cmd

import (
	"fmt"
	"os"
	"sync"
	"unicode/utf8"

	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
)

// spinnerMessageWidth is the fixed cell width the Describe label
// occupies. The bar + percent + count + elapsed/ETA add roughly
// another 45 cells; the total line lands around 100 columns, which
// is a comfortable fit for modern terminals. Keeping the label at
// a fixed width avoids redraw artefacts when a new message is
// shorter than the previous one (progressbar/v3 renders with `\r`
// and does not clear trailing glyphs).
const spinnerMessageWidth = 52

// progressSpinner wraps schollz/progressbar/v3 to give the analyze
// command a modern, thick-block progress bar driven by the same
// Update(step, total, message) interface the legacy hand-rolled
// spinner exposed. Only the visual rendering changes — no change to
// orchestration or log plumbing is needed upstream.
type progressSpinner struct {
	mu  sync.Mutex
	bar *progressbar.ProgressBar
}

// newSpinner returns an uninitialised progressSpinner. The underlying
// progress bar is created lazily on the first Update call, at which
// point the total step count is known.
func newSpinner() *progressSpinner {
	return &progressSpinner{}
}

// Start is a no-op kept for interface compatibility with the legacy
// spinner — progressbar/v3 self-renders on every Set/Describe call.
func (s *progressSpinner) Start() {}

// Stop finalises the progress bar and clears the line so the
// post-analysis output starts on a clean row.
func (s *progressSpinner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bar == nil {
		return
	}
	_ = s.bar.Finish()
	fmt.Fprint(os.Stderr, "\r\033[K")
}

// Update sets the progress to step/total and updates the label. It is
// safe to call concurrently. The total may grow across calls (the
// GitHub remote path emits its listing+fetch ticks before the final
// grand total is known, then bumps the total once enrichment +
// branch-protection slots are counted). When total changes, the bar
// is recreated rather than resized with ChangeMax: progressbar/v3
// latches `state.finished=true` the first time currentNum reaches
// the old max, and that flag short-circuits every subsequent render
// even after the max grows. Recreating yields a fresh state and the
// late "Resolving branch protection" tick actually paints.
func (s *progressSpinner) Update(step, total int, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bar == nil || int64(total) != s.bar.GetMax64() {
		if s.bar != nil {
			// Clear the existing bar's line in place before swapping.
			// Without this, ANSI residue from the prior render bleeds
			// into the new bar's first paint.
			fmt.Fprint(os.Stderr, "\r\033[K")
		}
		s.bar = progressbar.NewOptions(total,
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWidth(20),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "█",
				SaucerHead:    "█",
				SaucerPadding: "░",
				BarStart:      "",
				BarEnd:        "",
			}),
			progressbar.OptionSetRenderBlankState(true),
			progressbar.OptionClearOnFinish(),
		)
	}
	s.bar.Describe(fmt.Sprintf("  %s", padOrTruncate(message, spinnerMessageWidth)))
	_ = s.bar.Set(step)
}

// padOrTruncate returns message cut or padded to exactly width
// runes. Long identifiers like action names are truncated with an
// ellipsis so the spinner line keeps a stable width and the
// progress bar does not jump as the message changes.
func padOrTruncate(message string, width int) string {
	if width <= 0 {
		return ""
	}
	n := utf8.RuneCountInString(message)
	if n == width {
		return message
	}
	if n < width {
		return message + padding(width-n)
	}
	// Truncate with a trailing ellipsis. Common UI convention, keeps
	// the prefix visible — which for our messages is the most
	// informative part (`Resolving action <owner>/…`).
	if width <= 1 {
		return message[:width]
	}
	runes := []rune(message)
	return string(runes[:width-1]) + "…"
}

func padding(n int) string {
	if n <= 0 {
		return ""
	}
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = ' '
	}
	return string(buf)
}

// InstallLogHook registers a logrus hook that blanks the current line
// before a log record is emitted. Without it the progress bar and the
// log message would fight for the same terminal row and both would
// end up garbled.
func (s *progressSpinner) InstallLogHook() {
	logrus.AddHook(&spinnerLogHook{s: s})
}

type spinnerLogHook struct {
	s *progressSpinner
}

func (h *spinnerLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *spinnerLogHook) Fire(_ *logrus.Entry) error {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	fmt.Fprint(os.Stderr, "\r\033[K")
	return nil
}
