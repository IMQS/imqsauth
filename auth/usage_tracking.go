package imqsauth

import (
	"sync"
	"time"

	"github.com/IMQS/authaus"
)

// CheckLogEntry represents a single session check log entry
type CheckLogEntry struct {
	Timestamp    time.Time       `json:"timestamp"`
	SessionToken string          `json:"session_token"`
	Identity     string          `json:"identity"`
	UserId       authaus.UserId  `json:"user_id"`
	Username     string          `json:"username"`
	Email        string          `json:"email"`
}

// CheckUsageTracker manages in-memory storage and periodic flushing of session check logs
type CheckUsageTracker struct {
	config      *UsageTrackingConfig
	central     *ImqsCentral
	logs        []CheckLogEntry
	mutex       sync.RWMutex
	stopChan    chan struct{}
	flushTicker *time.Ticker
}

// NewCheckUsageTracker creates a new usage tracker instance
func NewCheckUsageTracker(config *UsageTrackingConfig, central *ImqsCentral) *CheckUsageTracker {
	tracker := &CheckUsageTracker{
		config:   config,
		central:  central,
		logs:     make([]CheckLogEntry, 0),
		stopChan: make(chan struct{}),
	}

	if config != nil && config.Enabled {
		tracker.start()
	}

	return tracker
}

// LogCheck adds a check request to the in-memory log
func (t *CheckUsageTracker) LogCheck(sessionToken string, token *authaus.Token) {
	if t.config == nil || !t.config.Enabled {
		return
	}

	entry := CheckLogEntry{
		Timestamp:    time.Now().UTC(),
		SessionToken: sessionToken,
		Identity:     token.Identity,
		UserId:       token.UserId,
		Username:     token.Username,
		Email:        token.Email,
	}

	t.mutex.Lock()
	t.logs = append(t.logs, entry)
	t.mutex.Unlock()
}

// start begins the periodic flush process
func (t *CheckUsageTracker) start() {
	flushInterval := time.Duration(t.config.FlushInterval) * time.Second
	if flushInterval <= 0 {
		flushInterval = 60 * time.Second // Default to 1 minute
	}

	t.flushTicker = time.NewTicker(flushInterval)

	go func() {
		for {
			select {
			case <-t.flushTicker.C:
				t.flush()
			case <-t.stopChan:
				t.flushTicker.Stop()
				t.flush() // Final flush before stopping
				return
			}
		}
	}()
}

// flush writes the in-memory logs to persistent storage and clears the memory
func (t *CheckUsageTracker) flush() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if len(t.logs) == 0 {
		return
	}

	// Create a copy of logs to persist
	logsToPersist := make([]CheckLogEntry, len(t.logs))
	copy(logsToPersist, t.logs)

	// Clear the in-memory logs
	t.logs = t.logs[:0]

	// Persist logs in a separate goroutine to avoid blocking
	go func() {
		if err := t.persistLogs(logsToPersist); err != nil {
			t.central.Central.Log.Errorf("Failed to persist check usage logs: %v", err)
		}
	}()
}

// persistLogs writes logs to persistent storage using authaus persistence abstraction
func (t *CheckUsageTracker) persistLogs(logs []CheckLogEntry) error {
	// For now, we'll use the existing logging infrastructure
	// In a production implementation, this would use a proper database table
	// via the authaus persistence layer
	
	for _, entry := range logs {
		t.central.Central.Log.Infof("CheckUsage: time=%v token=%s identity=%s userId=%d username=%s email=%s",
			entry.Timestamp.Format(time.RFC3339),
			entry.SessionToken,
			entry.Identity,
			entry.UserId,
			entry.Username,
			entry.Email,
		)
	}

	return nil
}

// Stop gracefully shuts down the usage tracker
func (t *CheckUsageTracker) Stop() {
	if t.config != nil && t.config.Enabled && t.flushTicker != nil {
		close(t.stopChan)
	}
}