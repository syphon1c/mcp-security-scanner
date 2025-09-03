# MCP Security Proxy - API Documentation

This document describes the REST API endpoints available for monitoring the MCP Security Proxy in real-time.

## Base URL

When the proxy is running on port `9081`, the base URL for monitoring endpoints is:
```
http://localhost:9081
```

## Authentication

Currently, the proxy monitoring endpoints do not require authentication. In production deployments, ensure these endpoints are protected by appropriate network security measures or authentication middleware.

## Endpoints

### Health Check

Check the overall health and status of the proxy service.

**Endpoint:** `GET /monitor/health`

**Response Format:**
```json
{
  "status": "healthy",
  "timestamp": "2025-09-02T12:34:56.789Z",
  "target": "http://localhost:8000",
  "alerts_queue_size": 5,
  "logs_queue_size": 142
}
```

**Response Fields:**
- `status` (string): Health status - "healthy" or "unhealthy"
- `timestamp` (ISO 8601 string): Current server timestamp
- `target` (string): URL of the target MCP server being proxied
- `alerts_queue_size` (integer): Number of pending security alerts in queue
- `logs_queue_size` (integer): Number of pending log entries in queue

**Example Request:**
```bash
curl -X GET http://localhost:9081/monitor/health
```

**Response Codes:**
- `200 OK`: Service is healthy
- `500 Internal Server Error`: Service is experiencing issues

---

### Security Alerts

Retrieve recent security alerts detected by the proxy.

**Endpoint:** `GET /monitor/alerts`

**Query Parameters:**
- `limit` (optional): Maximum number of alerts to return (default: 100)
- `severity` (optional): Filter by severity level (Critical, High, Medium, Low)
- `since` (optional): ISO 8601 timestamp - only return alerts after this time

**Response Format:**
```json
{
  "status": "ok",
  "message": "Alert endpoint active",
  "count": 3,
  "alerts": [
    {
      "timestamp": "2025-09-02T12:30:15.123Z",
      "severity": "Critical",
      "alertType": "Command Injection",
      "description": "Detected potential command injection in MCP tool call",
      "source": "192.168.1.100",
      "evidence": "subprocess.run(user_input, shell=True)",
      "action": "blocked"
    },
    {
      "timestamp": "2025-09-02T12:28:45.456Z",
      "severity": "High",
      "alertType": "SQL Injection",
      "description": "Detected SQL injection attempt in resource query",
      "source": "192.168.1.100",
      "evidence": "SELECT * FROM users WHERE id = ' OR '1'='1",
      "action": "logged"
    }
  ]
}
```

**Alert Object Fields:**
- `timestamp` (ISO 8601 string): When the alert was generated
- `severity` (string): Alert severity level (Critical, High, Medium, Low)
- `alertType` (string): Type of security issue detected
- `description` (string): Human-readable description of the alert
- `source` (string): Source IP address or identifier
- `evidence` (string): Code or data that triggered the alert
- `action` (string): Action taken (blocked, logged, allowed)

**Example Requests:**
```bash
# Get all recent alerts
curl -X GET http://localhost:9081/monitor/alerts

# Get only critical alerts
curl -X GET "http://localhost:9081/monitor/alerts?severity=Critical"

# Get alerts from the last hour
curl -X GET "http://localhost:9081/monitor/alerts?since=2025-09-02T11:00:00Z"
```

**Response Codes:**
- `200 OK`: Successfully retrieved alerts
- `400 Bad Request`: Invalid query parameters
- `500 Internal Server Error`: Error retrieving alerts

---

### Proxy Logs

Retrieve detailed logs of MCP traffic processed by the proxy.

**Endpoint:** `GET /monitor/logs`

**Query Parameters:**
- `limit` (optional): Maximum number of log entries to return (default: 100)
- `risk` (optional): Filter by risk level (Critical, High, Medium, Low, Minimal)
- `method` (optional): Filter by HTTP method (GET, POST, etc.)
- `since` (optional): ISO 8601 timestamp - only return logs after this time

**Response Format:**
```json
{
  "status": "ok",
  "message": "Logs endpoint active",
  "count": 2,
  "logs": [
    {
      "timestamp": "2025-09-02T12:35:22.789Z",
      "method": "POST",
      "request": {
        "url": "/mcp/tools/call",
        "headers": {
          "Content-Type": "application/json",
          "User-Agent": "MCP-Client/1.0"
        },
        "body": {
          "jsonrpc": "2.0",
          "method": "tools/call",
          "params": {
            "name": "execute_command",
            "arguments": {
              "command": "ls -la"
            }
          }
        }
      },
      "response": {
        "status": 200,
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "jsonrpc": "2.0",
          "result": {
            "content": [
              {
                "type": "text",
                "text": "total 16\ndrwxr-xr-x 4 user user 4096 Sep 2 12:35 ."
              }
            ]
          }
        }
      },
      "duration": "45ms",
      "risk": "Medium"
    }
  ]
}
```

**Log Object Fields:**
- `timestamp` (ISO 8601 string): When the request was processed
- `method` (string): HTTP method used
- `request` (object): Complete request details including URL, headers, and body
- `response` (object): Complete response details including status, headers, and body
- `duration` (string): Time taken to process the request
- `risk` (string): Risk level assigned to this transaction

**Example Requests:**
```bash
# Get all recent logs
curl -X GET http://localhost:9081/monitor/logs

# Get only high-risk transactions
curl -X GET "http://localhost:9081/monitor/logs?risk=High"

# Get POST requests only
curl -X GET "http://localhost:9081/monitor/logs?method=POST"
```

**Response Codes:**
- `200 OK`: Successfully retrieved logs
- `400 Bad Request`: Invalid query parameters
- `500 Internal Server Error`: Error retrieving logs

---

## WebSocket Endpoint

The proxy also provides a WebSocket endpoint for real-time streaming of alerts and logs.

**Endpoint:** `WS /ws`

**Connection:**
```javascript
const ws = new WebSocket('ws://localhost:9081/ws');

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    if (data.type === 'alert') {
        console.log('Security Alert:', data.payload);
    } else if (data.type === 'log') {
        console.log('Proxy Log:', data.payload);
    }
};
```

**Message Format:**
```json
{
  "type": "alert",
  "timestamp": "2025-09-02T12:40:00.000Z",
  "payload": {
    "timestamp": "2025-09-02T12:40:00.000Z",
    "severity": "Critical",
    "alertType": "Command Injection",
    "description": "Detected potential command injection",
    "source": "192.168.1.100",
    "evidence": "subprocess.run(user_input, shell=True)",
    "action": "blocked"
  }
}
```

## Error Handling

All endpoints return JSON responses with appropriate HTTP status codes. Error responses follow this format:

```json
{
  "status": "error",
  "error": "Error description",
  "code": "ERROR_CODE",
  "timestamp": "2025-09-02T12:45:00.000Z"
}
```

## Rate Limiting

Currently, no rate limiting is implemented on monitoring endpoints. In production, consider implementing rate limiting to prevent abuse.

## Security Considerations

1. **Network Security**: Ensure monitoring endpoints are only accessible from trusted networks
2. **Authentication**: Implement authentication for production deployments
3. **Data Sensitivity**: Log data may contain sensitive information - handle appropriately
4. **HTTPS**: Use HTTPS in production environments
5. **Access Logs**: Monitor access to these endpoints for security audit purposes

## Integration Examples

### SIEM Integration

```python
import requests
import time

def poll_alerts(proxy_url, siem_webhook):
    """Poll for new alerts and forward to SIEM"""
    last_check = time.time() - 3600  # Start with last hour
    
    while True:
        since = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(last_check))
        response = requests.get(f"{proxy_url}/monitor/alerts", 
                              params={'since': since})
        
        if response.status_code == 200:
            data = response.json()
            for alert in data.get('alerts', []):
                # Forward to SIEM
                requests.post(siem_webhook, json=alert)
        
        last_check = time.time()
        time.sleep(30)  # Poll every 30 seconds

# Usage
poll_alerts('http://localhost:9081', 'https://siem.company.com/webhook')
```

### Dashboard Integration

```javascript
// Real-time dashboard using WebSocket
class ProxyDashboard {
    constructor(proxyUrl) {
        this.ws = new WebSocket(`ws://${proxyUrl}/ws`);
        this.setupEventHandlers();
    }
    
    setupEventHandlers() {
        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'alert') {
                this.displayAlert(data.payload);
            } else if (data.type === 'log') {
                this.updateTrafficChart(data.payload);
            }
        };
    }
    
    displayAlert(alert) {
        // Update dashboard with new alert
        console.log('New Alert:', alert);
    }
    
    updateTrafficChart(log) {
        // Update traffic visualization
        console.log('New Traffic:', log);
    }
}

// Usage
const dashboard = new ProxyDashboard('localhost:9081');
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure the proxy is running and listening on the correct port
2. **Empty Responses**: Check if any MCP traffic has been processed by the proxy
3. **WebSocket Disconnects**: Implement reconnection logic in client applications
4. **High Memory Usage**: Monitor queue sizes via `/monitor/health` endpoint

### Debug Mode

Enable debug logging by setting the `DEBUG` environment variable:
```bash
DEBUG=1 ./mcpscan proxy http://localhost:8000 9081 critical-security
```

This will provide additional logging information for troubleshooting.
