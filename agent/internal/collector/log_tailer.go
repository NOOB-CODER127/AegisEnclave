package collector

import (
	"log"
	"regexp"
	"time"

	"github.com/nxadm/tail"
)

type LogLine struct {
	Timestamp time.Time
	Content   string
	Path      string
}

type LogTailer struct {
	Path    string
	Out     chan LogLine
	tailObj *tail.Tail
}

func NewLogTailer(path string, outChan chan LogLine) (*LogTailer, error) {
	return &LogTailer{
		Path: path,
		Out:  outChan,
	}, nil
}

func (l *LogTailer) Start() error {
	t, err := tail.TailFile(l.Path, tail.Config{
		Follow: true,
		ReOpen: true, // Reopen if file gets rotated
		Poll:   true, // Use polling if watcher fails
		Logger: tail.DiscardingLogger,
	})
	if err != nil {
		return err
	}
	l.tailObj = t

	go func() {
		for line := range t.Lines {
			ts := line.Time
			if parsed, ok := tryParseTimestamp(line.Text); ok {
				ts = parsed
			}
			l.Out <- LogLine{
				Timestamp: ts,
				Content:   line.Text,
				Path:      l.Path,
			}
		}
	}()

	log.Printf("Started tailing: %s", l.Path)
	return nil
}

func (l *LogTailer) Stop() {
	if l.tailObj != nil {
		l.tailObj.Stop()
	}
}

func tryParseTimestamp(content string) (time.Time, bool) {
	// 1. Try "Mon Jan 02 03:04:05 PM MST 2006" (e.g., from generated logs)
	// Regex: [A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{1,2}:\d{2}:\d{2} (AM|PM) [A-Z]+ \d{4}
	// Example: Mon Jan 12 10:45:18 AM UTC 2026
	longDateRegex := regexp.MustCompile(`[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)\s+[A-Z]+\s+\d{4}`)
	if match := longDateRegex.FindString(content); match != "" {
		if t, err := time.Parse("Mon Jan 02 03:04:05 PM MST 2006", match); err == nil {
			return t, true
		}
	}

	// 2. Try ISO8601/RFC3339 candidates (e.g. 2023-01-01 12:00:00)
	isoRegex := regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`)
	if match := isoRegex.FindString(content); match != "" {
		// Try parsing with a few common layouts
		layouts := []string{
			time.RFC3339,
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, match); err == nil {
				return t, true
			}
		}
	}

	return time.Time{}, false
}
