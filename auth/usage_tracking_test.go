package imqsauth

import (
	"testing"
	"time"

	"github.com/IMQS/authaus"
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
		if entry.Identity != token.Identity {
			t.Errorf("Expected identity %s, got %s", token.Identity, entry.Identity)
		}
		if entry.UserId != token.UserId {
			t.Errorf("Expected userId %d, got %d", token.UserId, entry.UserId)
		}
		if entry.Username != token.Username {
			t.Errorf("Expected username %s, got %s", token.Username, entry.Username)
		}
		if entry.Email != token.Email {
			t.Errorf("Expected email %s, got %s", token.Email, entry.Email)
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