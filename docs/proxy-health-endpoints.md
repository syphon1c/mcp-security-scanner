# MCP Security Proxy - Health Check Endpoints

The MCP Security Proxy provides comprehensive monitoring endpoints for operational visibility and health checking.

## Health Check Endpoint

**URL**: `GET /monitor/health`

### Response Format

```json
{
  "status": "healthy|degraded|critical",
  "timestamp": "2025-09-03T10:30:00Z",
  "proxy_version": "1.0.0",
  "target": "https://target-mcp-server.com",
  "alerts_queue_size": 5,
  "alerts_queue_usage": "5.0%",
  "logs_queue_size": 12,
  "logs_queue_usage": "1.2%",
  "traffic_analyzer": true,
  "alert_processor": true,
  "policies_loaded": 3
}
```

### Health Status Levels

- **healthy**: All systems operating normally
  - Queue usage < 90%
  - HTTP Status: 200 OK

- **degraded**: System functioning but showing stress
  - Queue usage 90-99%
  - HTTP Status: 200 OK

- **critical**: System at capacity, may drop requests
  - Queue usage ≥ 100%
  - HTTP Status: 503 Service Unavailable

## Monitoring Endpoints

### Alerts Endpoint
**URL**: `GET /monitor/alerts`

Returns recent security alerts (simplified implementation).

```json
{
  "status": "ok",
  "message": "Alert endpoint active",
  "alerts": []
}
```

### Logs Endpoint
**URL**: `GET /monitor/logs`

Returns recent proxy logs (simplified implementation).

```json
{
  "status": "ok", 
  "message": "Logs endpoint active",
  "logs": []
}
```

## Usage Examples

### Basic Health Check
```bash
curl -X GET http://localhost:8080/monitor/health
```

### Health Check with Response Status
```bash
# Returns 200 for healthy/degraded, 503 for critical
curl -w "%{http_code}" -X GET http://localhost:8080/monitor/health
```

### Monitoring Script Example
```bash
#!/bin/bash
PROXY_URL="http://localhost:8080"

# Check health status
HEALTH=$(curl -s "${PROXY_URL}/monitor/health")
STATUS=$(echo "$HEALTH" | jq -r '.status')

case "$STATUS" in
  "healthy")
    echo "✅ Proxy is healthy"
    exit 0
    ;;
  "degraded")
    echo "⚠️ Proxy is degraded - check queue usage"
    exit 1
    ;;
  "critical")
    echo "🚨 Proxy is critical - immediate attention required"
    exit 2
    ;;
  *)
    echo "❌ Unknown proxy status: $STATUS"
    exit 3
    ;;
esac
```

## Integration with Monitoring Tools

### Prometheus/Grafana
The health endpoint can be scraped by Prometheus for metrics collection and alerting.

### Load Balancer Health Checks
Configure your load balancer to use `/monitor/health` with:
- **Path**: `/monitor/health`
- **Expected Status**: `200` (for healthy/degraded)
- **Health Check Interval**: 30 seconds
- **Timeout**: 5 seconds

### Container Orchestration
For Docker/Kubernetes deployments:

```yaml
livenessProbe:
  httpGet:
    path: /monitor/health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /monitor/health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

## Operational Considerations

- **Queue Monitoring**: Watch `alerts_queue_usage` and `logs_queue_usage` percentages
- **Alert Thresholds**: Consider alerting at 80% queue usage to prevent degradation
- **Capacity Planning**: High queue usage indicates need for scaling or optimization
- **Troubleshooting**: Check `traffic_analyzer` and `alert_processor` booleans for component health
