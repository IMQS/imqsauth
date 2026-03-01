# Session Check Usage Tracking

This document describes the session check usage tracking feature implemented in imqsauth.

## Overview

The usage tracking feature monitors calls to the `/check` endpoint, logging session activity for analysis. This helps track user activity and system usage patterns.

## Configuration

Usage tracking is controlled by the `UsageTracking` section in the configuration file:

```json
{
  "UsageTracking": {
    "enabled": false,
    "flush_interval": 60
  }
}
```

### Configuration Options

- `enabled` (bool): Enable or disable usage tracking. Default: `false`
- `flush_interval` (int): Interval in seconds for flushing logs to persistent storage. Default: `60`

## How It Works

1. **Request Logging**: When enabled, successful `/check` requests are logged in memory
2. **Data Captured**: Each log entry includes:
   - Timestamp (UTC)
   - Session token
   - User identity
   - User ID
   - Username
   - Email address
3. **Periodic Flushing**: Logs are flushed to persistent storage at the configured interval
4. **Error Handling**: Logging failures do not disrupt user experience

## Logged Events

Only successful check requests are logged:
- Valid session token
- User has "enabled" permission
- Request completes successfully

Expired sessions and disabled users are not logged since they fail validation.

## Storage

Currently, logs are written to the application log file with the prefix "CheckUsage:". In production deployments, this can be extended to use database storage through the authaus persistence layer.

## Security Considerations

- Session tokens are logged for correlation purposes
- Logs should be treated as sensitive data
- Consider log retention policies for compliance
- Ensure proper access controls on log files

## Example Log Entry

```
CheckUsage: time=2024-01-15T10:30:45Z token=abc123session identity=john.doe userId=42 username=john.doe email=john.doe@example.com
```