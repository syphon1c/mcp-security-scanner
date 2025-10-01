# LM-Specific Web Dashboard

## Overview

A web-based dashboard specifically designed for LLM (Large Language Model) security monitoring. This dashboard provides real-time visibility into LLM API traffic, security threats, token usage, and cost analysis.

## Features Implemented

### 🖥️ LLM Admin Dashboard (`/admin/llm`)
- **Real-time Monitoring**: Live updates every 30 seconds
- **Provider Detection**: Automatic identification of LLM providers (OpenAI, Claude, Google, Cohere)
- **Token Usage Tracking**: Comprehensive token consumption analytics
- **Cost Estimation**: Real-time cost calculations for API usage
- **Security Monitoring**: Live threat detection and alerting

### 📊 Analytics & Visualizations

#### Token Usage Analytics (`/admin/llm/tokens`)
- Total token consumption tracking
- Token usage by model
- Hourly token consumption patterns
- Cost estimation based on token usage
- Top models by usage
- Daily and weekly usage trends

#### Request Statistics (`/api/llm/stats`)
- Total request counts
- Success/failure rates
- Average response latency
- Request patterns by provider
- Hourly request distribution

#### Security Threat Analysis (`/admin/llm/threats`)
- Threat categorization and counting
- Real-time threat detection
- Severity-based threat classification
- Historical threat patterns
- Top threats by frequency

### 🔒 Security Features

#### LLM-Specific Policy Management
- Dedicated LLM policy loading (policy_type: "llm")
- Prompt injection detection
- Jailbreaking attempt monitoring
- PII exposure prevention
- Secret leakage detection
- Token abuse protection

#### Real-time Alert System
- Security alerts with severity levels (Critical, High, Medium, Low)
- Alert categorization:
  - Prompt Injection
  - Jailbreaking
  - PII Exposure
  - Secret Leakage
  - Content Policy Violations
  - Token Abuse

### 🎨 User Interface

#### Professional Dashboard Design
- Modern, responsive web interface
- Mobile-friendly design
- Dark/light theme compatibility
- Intuitive navigation
- Real-time data updates

#### Interactive Elements
- Auto-refresh functionality
- Hover effects and animations
- Progress bars and charts
- Sortable data tables
- Expandable alert details

## Technical Architecture

### Backend Components

#### LLMAdminServer (`internal/web/llm_admin.go`)
```go
type LLMAdminServer struct {
    policies       map[string]*types.SecurityPolicy
    policyDir      string
    alertHistory   []types.SecurityAlert
    llmLogs        []types.LLMProxyLog
    tokenUsage     *LLMTokenUsage
    requestStats   *LLMRequestStats
    // ... additional fields
}
```

#### Key Data Structures
- `LLMTokenUsage`: Token consumption tracking
- `LLMRequestStats`: Request performance metrics
- `LLMProxyLog`: Detailed traffic logs
- `ThreatSummary`: Security threat analysis

#### Integration with LLM Proxy
```go
// In LLMProxy struct
adminServer *web.LLMAdminServer

// Background processing
func (p *LLMProxy) processLogs() {
    for logEntry := range p.logChan {
        p.adminServer.RecordLLMActivity(logEntry)
        // Additional processing...
    }
}
```

### Frontend Components

#### HTML Templates (`web/templates/llm/`)
- `llm_dashboard.html`: Main dashboard template
- Responsive CSS with modern styling
- Progressive enhancement for JavaScript features

#### JavaScript Functionality (`web/static/llm/dashboard.js`)
- `LLMDashboard` class for dashboard management
- Auto-refresh functionality
- Chart rendering and data visualization
- Real-time metric updates
- Error handling and user feedback

### API Endpoints

#### Dashboard Data
- `GET /api/llm/dashboard`: Complete dashboard data
- `GET /api/llm/tokens`: Token usage statistics
- `GET /api/llm/stats`: Request performance data
- `GET /api/llm/threats`: Security threat data
- `GET /api/llm/models`: Model usage statistics
- `GET /api/llm/logs`: Recent proxy logs

#### Policy Management
- `GET /api/llm/policies`: LLM-specific policies
- `POST /api/llm/policies/reload`: Reload LLM policies

## Configuration

### Policy Type Separation
LLM policies are identified by the `policy_type` field:
```json
{
    "policy_type": "llm",
    "policyName": "llm-security",
    "description": "LLM-specific security policies"
}
```

### Web Server Integration
The LLM admin server integrates with the existing proxy:
```go
// Add LLM admin routes to proxy
p.adminServer.AddRoutes(router)
```

## Usage Examples

### Starting LLM Proxy with Dashboard
```bash
# Start LLM proxy for OpenAI
./mcpscan llm-proxy https://api.openai.com/v1 8080

# Start LLM proxy for Claude
./mcpscan llm-proxy https://api.anthropic.com/v1 8080
```

### Accessing the Dashboard
- Main Dashboard: `http://localhost:8080/admin/llm`
- Token Analytics: `http://localhost:8080/admin/llm/tokens`
- Threat Analysis: `http://localhost:8080/admin/llm/threats`
- Model Statistics: `http://localhost:8080/admin/llm/models`

### API Access
```bash
# Get dashboard data
curl http://localhost:8080/api/llm/dashboard

# Get token usage
curl http://localhost:8080/api/llm/tokens

# Get security threats
curl http://localhost:8080/api/llm/threats
```

## Monitoring & Analytics

### Token Usage Tracking
- Real-time token consumption
- Per-model usage breakdown
- Cost estimation with provider-specific pricing
- Usage trends and patterns

### Security Monitoring
- Live threat detection
- Alert severity classification
- Threat pattern analysis
- Historical security metrics

### Performance Analytics
- Request/response latency
- Success/failure rates
- Provider performance comparison
- Load patterns and capacity planning

## Browser Compatibility

The dashboard is tested and compatible with:
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+
- Mobile browsers (iOS Safari, Chrome Mobile)

## Performance Considerations

### Data Retention
- Alert history: 1,000 most recent alerts
- Log entries: 5,000 most recent logs
- Token data: Configurable retention period
- Automatic cleanup of old data

### Real-time Updates
- Auto-refresh every 30 seconds
- Efficient diff-based updates
- Lazy loading for large datasets
- Optimized API responses

## Security Considerations

### Access Control
- Dashboard accessible only via proxy interface
- No external authentication required (proxy-level security)
- Rate limiting on API endpoints

### Data Privacy
- Sensitive data filtering in logs
- Configurable PII masking
- Secure data transmission (HTTPS when configured)

## Troubleshooting

### Common Issues

#### Dashboard Not Loading
1. Verify proxy is running: `curl http://localhost:PORT/monitor/health`
2. Check log output for errors
3. Ensure LLM policies are loaded correctly

#### Data Not Updating
1. Check auto-refresh is enabled
2. Verify API endpoints are responding: `curl http://localhost:PORT/api/llm/dashboard`
3. Check browser console for JavaScript errors

#### Missing Metrics
1. Ensure LLM traffic is flowing through proxy
2. Verify policy configuration
3. Check log processing pipeline

### Debug Mode
Enable verbose logging for troubleshooting:
```bash
./mcpscan llm-proxy https://api.openai.com/v1 8080 --log-level debug
```

## Future Enhancements

### Planned Features
- Advanced charting library integration (Chart.js, D3.js)
- Export functionality (PDF reports, CSV data)
- Alerting integrations (Slack, email, webhooks)
- Custom dashboard widgets
- Multi-tenant support
- Historical data persistence

### API Improvements
- GraphQL endpoint for flexible data queries
- WebSocket support for real-time updates
- Bulk operations for policy management
- Advanced filtering and search

## Integration Examples

### SIEM Integration
```json
{
    "timestamp": "2024-01-01T12:00:00Z",
    "event_type": "llm_threat_detected",
    "severity": "high",
    "threat_category": "prompt_injection",
    "details": {
        "provider": "openai",
        "model": "gpt-4",
        "client_ip": "192.168.1.100"
    }
}
```

### Monitoring Integration
```bash
# Prometheus metrics endpoint
curl http://localhost:8080/metrics

# Health check endpoint
curl http://localhost:8080/monitor/health
```
