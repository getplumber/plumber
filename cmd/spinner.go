package cmd

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// progressSpinner displays a progress indicator on stderr during long-running operations.
// It shows an animated spinner with the current step message and a progress bar.
type progressSpinner struct {
	mu      sync.Mutex
	step    int
	total   int
	message string
	done    chan struct{}
	stopped chan struct{}
	started bool
}

// newSpinner creates a new progressSpinner. Call Start() to begin animation.
func newSpinner() *progressSpinner {
	return &progressSpinner{
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

// spinnerFrames are the spinner animation characters
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Update sets the current progress step and message.
// This is safe to call from any goroutine.
func (s *progressSpinner) Update(step, total int, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.step = step
	s.total = total
	s.message = message
}

// ClearLine erases the spinner line so log output can print cleanly.
func (s *progressSpinner) ClearLine() {
	if s.started {
		fmt.Fprintf(os.Stderr, "\r\033[K")
	}
}

// spinnerLogHook is a logrus hook that clears the spinner line before each log entry.
type spinnerLogHook struct {
	spinner *progressSpinner
}

func (h *spinnerLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *spinnerLogHook) Fire(_ *logrus.Entry) error {
	h.spinner.ClearLine()
	return nil
}

// InstallLogHook adds a logrus hook that clears the spinner line before each log message.
// This prevents log output from being interleaved with the spinner animation.
func (s *progressSpinner) InstallLogHook() {
	logrus.AddHook(&spinnerLogHook{spinner: s})
}

// Start begins the spinner animation in a background goroutine.
// The spinner renders to stderr so it doesn't interfere with stdout output.
func (s *progressSpinner) Start() {
	s.started = true
	go func() {
		defer close(s.stopped)
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		frameIdx := 0

		for {
			select {
			case <-s.done:
				// Render final completion state before clearing
				s.mu.Lock()
				step := s.step
				total := s.total
				msg := s.message
				s.mu.Unlock()

				if total > 0 {
					bar := ""
					for i := 0; i < 20; i++ {
						bar += "█"
					}
					fmt.Fprintf(os.Stderr, "\r\033[K  ✓ [%s] (%d/%d) %s\n", bar, step, total, msg)
				} else {
					fmt.Fprintf(os.Stderr, "\r\033[K")
				}
				return
			case <-ticker.C:
				s.mu.Lock()
				step := s.step
				total := s.total
				msg := s.message
				s.mu.Unlock()

				if total == 0 {
					continue
				}

				frame := spinnerFrames[frameIdx%len(spinnerFrames)]
				frameIdx++

				// Build progress bar
				barWidth := 20
				filled := 0
				if total > 0 {
					filled = (step * barWidth) / total
				}
				if filled > barWidth {
					filled = barWidth
				}

				bar := ""
				for i := 0; i < barWidth; i++ {
					if i < filled {
						bar += "█"
					} else {
						bar += "░"
					}
				}

				// Render: ⠋ [████████░░░░░░░░░░░░] (3/14) Collecting pipeline origins
				line := fmt.Sprintf("\r\033[K  %s [%s] (%d/%d) %s", frame, bar, step, total, msg)
				fmt.Fprint(os.Stderr, line)
			}
		}
	}()
}

// Stop terminates the spinner animation and waits for cleanup.
func (s *progressSpinner) Stop() {
	if s.started {
		close(s.done)
		<-s.stopped // wait for the goroutine to finish rendering
	}
}
