# MCP Security Scanner Web Administration Interface

The MCP Security Scanner now includes a built-in web administration interface that allows you to manage security policies, view alerts, and monitor proxy activity through a user-friendly web browser interface.

## Features

### Dashboard
- Overview of active policies and recent alerts
- Quick access to main administration functions
- Real-time system status monitoring

### Policy Management
- View all loaded security policies
- Browse policy rules and blocked patterns
- Add, edit, and delete security rules
- Manage blocked patterns for real-time blocking
- Policy versioning and backup (automatic backups created)

### Alert Monitoring  
- Real-time security alert viewing
- Filter alerts by severity (Critical, High, Medium, Low)
- Auto-refresh every 30 seconds
- Alert history and statistics
- Clear alerts functionality

### Proxy Health Monitoring
- View proxy status and performance metrics
- Monitor queue sizes and capacity
- Check target connectivity
- Performance statistics

## Access

When running the MCP Security Scanner in proxy mode, the web interface is automatically available at:

```
Main Dashboard:     http://localhost:<port>/admin
Policy Management:  http://localhost:<port>/admin/policies  
Alert Monitoring:   http://localhost:<port>/admin/alerts
```

## Usage

### Starting the Proxy with Web Interface

```bash
# Basic proxy mode (loads all policies from ./policies/ directory)
./mcpscan proxy http://target-server.com 9080

# Example with mock server running
./mcpscan proxy http://localhost:8010 8080
```

The web interface will be accessible at `http://localhost:8080/admin`

![Web Admin Dashboard](/docs/media/mcp_web_admin.png)

**Note**: The proxy automatically loads and applies ALL policy files (*.json) found in the `./policies/` directory. You cannot specify a single policy via command line to use only specific policies, remove unwanted policy files from the policies directory before starting the proxy.

### Managing Security Policies

![Edit Policies](/docs/media/mcp_web_policies_edit.png)

1. **View Policies**: Navigate to `/admin/policies` to see all loaded policies
2. **View Policy Details**: Click "View Details" on any policy card to see rules and blocked patterns
3. **Add New Rule**: 
   - Click "Add New Rule" in the Rules tab
   - Fill in required fields: ID, Name, Description, Category, Severity, Patterns
   - Click "Add" to save
4. **Delete Rule**: Click the "Delete" button next to any rule
5. **Add Blocked Pattern**:
   - Switch to "Blocked Patterns" tab
   - Click "Add New Pattern"
   - Specify pattern, type (regex/exact/contains), category, and description
6. **Delete Blocked Pattern**: Click "Delete" next to any blocked pattern

### Monitoring Alerts

![Security Alerts](/docs/media/mcp_web_alerts.png)

1. **View All Alerts**: Navigate to `/admin/alerts`
2. **Filter by Severity**: Use the filter buttons (All, Critical, High, Medium, Low)
3. **Refresh Manually**: Click the "Refresh" button
4. **Clear All Alerts**: Click "Clear All" (requires confirmation)
5. **Auto-refresh**: Alerts refresh automatically every 30 seconds

### Policy File Management

- **Automatic Backups**: When you modify a policy through the web interface, the system automatically creates timestamped backup files
- **File Location**: Policy files are stored in the `policies/` directory
- **Backup Format**: `<policy-name>.json.backup.<timestamp>`

## API Endpoints

The web interface uses these REST API endpoints:

### Policy Management
```
GET    /api/policies                    # List all policies
GET    /api/policies/{name}/rules       # Get rules for a policy
POST   /api/policies/{name}/rules       # Add new rule
PUT    /api/policies/{name}/rules/{id}  # Update existing rule
DELETE /api/policies/{name}/rules/{id}  # Delete rule

GET    /api/policies/{name}/blocked     # Get blocked patterns
POST   /api/policies/{name}/blocked     # Add blocked pattern  
DELETE /api/policies/{name}/blocked/{index} # Delete blocked pattern
```

### Alert Management
```
GET    /api/alerts       # Get all alerts
POST   /api/alerts/clear # Clear all alerts
```

### Monitoring
```
GET    /monitor/health   # Proxy health status
GET    /monitor/alerts   # Monitoring alerts (legacy)
GET    /monitor/logs     # Proxy logs (legacy)
```

## Security Considerations

### Access Control
- The web interface is currently open access - consider adding authentication for production use
- Runs on the same port as the proxy for simplicity
- Admin interface is accessible via `/admin` routes

### Policy Modifications
- Changes made through the web interface are immediately active
- Automatic backups are created before modifications
- Policy files are validated before saving

### Data Persistence
- Alerts are stored in memory (up to 1000 recent alerts)
- Policy changes are persisted to JSON files
- Configuration changes require proxy restart

## Customisation

### Styling
- CSS styles are in `web/static/style.css`
- Uses CSS custom properties for easy theme customisation
- Responsive design for mobile and desktop

### Templates
- HTML templates are in `web/templates/`
- Uses Go's `html/template` package
- Fallback rendering if templates are missing

### JavaScript
- Interactive functionality in `web/static/app.js`
- Modular API and UI utility functions
- Auto-refresh and error handling

## Troubleshooting

### Template Errors
If templates fail to load, the interface falls back to inline HTML rendering.

### Policy Save Failures
Check file permissions on the `policies/` directory and ensure the policy JSON is valid.

### API Errors
Check browser developer console for detailed error messages. Most API errors are logged on both client and server side.

### Memory Usage
Alert history is limited to 1000 entries to prevent memory issues. Consider implementing persistent storage for production use, this is for personal use currently.

## Development

### Adding New Features
1. Add API endpoints in `internal/web/admin.go`
2. Update templates in `web/templates/`
3. Add JavaScript functionality in `web/static/app.js`
4. Update styles in `web/static/style.css`

### Building
```bash
go build ./cmd/mcpscan
```

### Testing
The web interface can be tested by:
1. Starting the proxy: `./mcpscan proxy http://localhost:8010 8080`
2. Opening browser to `http://localhost:8080/admin`
3. Triggering security alerts with test payloads

## Integration with MCP Proxy

The web interface is fully integrated with the MCP Security Scanner proxy:

- **Real-time Alerts**: Security alerts from the proxy are immediately available in the web interface
- **Policy Updates**: Changes to policies through the web interface are immediately active in the proxy
- **Health Monitoring**: Web interface shows live proxy health and performance metrics
- **Unified Access**: Both proxy and admin interface run on the same port for simplified deployment

This provides a unified management experience for monitoring and administering your MCP security infrastructure.