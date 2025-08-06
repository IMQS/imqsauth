package imqsauth

import (
	"github.com/IMQS/authaus"
	"testing"
	"time"
)

func TestUsageTrackingConfig_SetDefaults(t *testing.T) {
	config := &UsageTrackingConfig{}
	config.SetDefaults()

	if config.FlushInterval != 60 {
		t.Errorf("Expected default FlushInterval to be 60, got %d", config.FlushInterval)
	}
}

func TestCheckUsageTracker_LogCheck_Disabled(t *testing.T) {
	// Test that when usage tracking is disabled, LogCheck does nothing
	config := &UsageTrackingConfig{Enabled: false}
	central := &ImqsCentral{}
	tracker := NewCheckUsageTracker(config, central)

	token := &authaus.Token{
		Identity: "testuser",
		UserId:   1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	// This should not panic or cause issues when disabled
	tracker.LogCheck("session123", token)

	// Should have no logs
	tracker.mutex.RLock()
	logCount := len(tracker.logs)
	tracker.mutex.RUnlock()

	if logCount != 0 {
		t.Errorf("Expected 0 logs when disabled, got %d", logCount)
	}
}

func TestCheckUsageTracker_LogCheck_Enabled(t *testing.T) {
	// Test that when usage tracking is enabled, LogCheck stores entries
	config := &UsageTrackingConfig{Enabled: true, FlushInterval: 60}
	central := &ImqsCentral{}
	tracker := NewCheckUsageTracker(config, central)
	defer tracker.Stop()

	token := &authaus.Token{
		Identity: "testuser",
		UserId:   1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	sessionToken := "session123"
	tracker.LogCheck(sessionToken, token)

	// Verify log was created
	tracker.mutex.RLock()
	logCount := len(tracker.logs)
	if logCount != 1 {
		t.Errorf("Expected 1 log entry, got %d", logCount)
	} else {
		entry := tracker.logs[0]
		if entry.SessionToken != sessionToken {
			t.Errorf("Expected session token %s, got %s", sessionToken, entry.SessionToken)
		}
		if entry.UserId != token.UserId {
			t.Errorf("Expected userId %d, got %d", token.UserId, entry.UserId)
		}
		if entry.Timestamp.IsZero() {
			t.Error("Expected timestamp to be set")
		}
	}
	tracker.mutex.RUnlock()
}

func TestCheckUsageTracker_NilConfig(t *testing.T) {
	// Test that tracker handles nil config gracefully
	central := &ImqsCentral{}
	tracker := NewCheckUsageTracker(nil, central)

	token := &authaus.Token{
		Identity: "testuser",
		UserId:   1,
	}

	// This should not panic
	tracker.LogCheck("session123", token)
	tracker.Stop()
}

func TestCheckUsageTracker_FlushBehavior(t *testing.T) {
	// Test that flush handles persistence failures correctly
	config := &UsageTrackingConfig{Enabled: true, FlushInterval: 1}
	central := &ImqsCentral{}
	tracker := NewCheckUsageTracker(config, central)
	defer tracker.Stop()

	// Add some logs
	token := &authaus.Token{
		Identity: "testuser",
		UserId:   1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	tracker.LogCheck("session1", token)
	tracker.LogCheck("session2", token)

	// Verify logs exist before flush
	tracker.mutex.RLock()
	initialCount := len(tracker.logs)
	tracker.mutex.RUnlock()

	if initialCount != 2 {
		t.Errorf("Expected 2 logs before flush, got %d", initialCount)
	}

	// Call flush manually
	tracker.flush()

	// Wait a bit for the goroutine to complete
	time.Sleep(100 * time.Millisecond)

	// Since persistLogs currently always succeeds (just logs),
	// logs should be cleared after flush
	tracker.mutex.RLock()
	finalCount := len(tracker.logs)
	flushing := tracker.flushing
	tracker.mutex.RUnlock()

	if finalCount != 0 {
		t.Errorf("Expected 0 logs after successful flush, got %d", finalCount)
	}

	if flushing {
		t.Error("Expected flushing to be false after flush completes")
	}
}
