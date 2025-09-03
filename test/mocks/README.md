# Mock MCP Server for Security Testing

This directory contains a  mock MCP (Model Context Protocol) server designed specifically for testing the MCP Security Scanner's remote scanning capabilities.

## ⚠️ Security Warning

**This mock server contains intentional security vulnerabilities for testing purposes only.**

- **DO NOT** use in production environments
- **DO NOT** expose to untrusted networks
- **ONLY** use for security testing and development

## Features

### MCP Protocol Implementation
- Full MCP 2024-11-05 protocol support
- HTTP and WebSocket endpoints
- Tool discovery and execution
- Resource listing and reading
- Proper JSON-RPC 2.0 message handling

### Intentional Vulnerabilities
The server includes the following vulnerabilities for testing:

1. **Command Injection** (RCE)
   - Tool: `execute_command`
   - Vulnerability: Direct shell command execution
   - Test: `{"name": "execute_command", "arguments": {"command": "id"}}`

2. **SQL Injection**
   - Tool: `query_database`
   - Vulnerability: Unsafe SQL query construction
   - Test: `{"name": "query_database", "arguments": {"query": "1=1 OR 1=1"}}`

3. **Path Traversal**
   - Tool: `read_file`
   - Vulnerability: Direct file access without sanitization
   - Test: `{"name": "read_file", "arguments": {"file_path": "../../../etc/passwd"}}`

4. **Cross-Site Scripting (XSS)**
   - Tool: `generate_report`
   - Vulnerability: Unsafe HTML generation
   - Test: `{"name": "generate_report", "arguments": {"title": "<script>alert('XSS')</script>"}}`

5. **Information Disclosure**
   - Endpoint: `/debug/info`
   - Vulnerability: Exposes sensitive server information
   - Test: `GET /debug/info`

6. **Insecure Resource Access**
   - Resource: `file:///etc/passwd`
   - Vulnerability: Direct file system access
   - Test: `{"uri": "file:///etc/passwd"}`

### Safe Mode
The server can run in safe mode with `--safe` flag, which disables all vulnerabilities while maintaining MCP protocol compatibility.

## Quick Start

### 1. Install Dependencies
```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Or use the setup script
./start-mock-server.sh
```

### 2. Start the Server
```bash
# Start in vulnerable mode (default)
python3 mock-mcp-server.py

# Start in safe mode
python3 mock-mcp-server.py --safe

# Custom host and port
python3 mock-mcp-server.py --host 0.0.0.0 --port 9000

# Verbose logging
python3 mock-mcp-server.py --verbose
```

### 3. Test the Server
```bash
# Test basic functionality
python3 test-mock-server.py

# Test with custom URL
python3 test-mock-server.py http://localhost:9000

# Manual health check
curl http://localhost:8000/health
```

### 4. Scan with MCP Security Scanner
```bash
# Basic security scan
./mcpscan scan-remote http://localhost:8000 critical-security

# Advanced polymorphic pattern detection
./mcpscan scan-remote http://localhost:8000 advanced-polymorphic-security

# Generate detailed report
./mcpscan scan-remote http://localhost:8000 critical-security --output-format html
```

## API Endpoints

### MCP Protocol Endpoints
- `POST /mcp/initialize` - Initialize MCP connection
- `POST /mcp/tools/list` - List available tools
- `POST /mcp/tools/call` - Execute tool
- `POST /mcp/resources/list` - List available resources
- `POST /mcp/resources/read` - Read resource content

### Management Endpoints
- `GET /health` - Health check and server info
- `GET /debug/info` - Debug information (VULNERABLE)
- `WS /ws` - WebSocket endpoint for MCP over WebSocket

## Example Requests

### Initialize Connection
```bash
curl -X POST http://localhost:8000/mcp/initialize \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {"tools": {}},
      "clientInfo": {"name": "Test Client", "version": "1.0.0"}
    }
  }'
```

### List Tools
```bash
curl -X POST http://localhost:8000/mcp/tools/list \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
  }'
```

### Execute Vulnerable Tool (Command Injection)
```bash
curl -X POST http://localhost:8000/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "execute_command",
      "arguments": {"command": "whoami"}
    }
  }'
```

### Read Vulnerable Resource
```bash
curl -X POST http://localhost:8000/mcp/resources/read \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "resources/read",
    "params": {"uri": "file:///etc/passwd"}
  }'
```

## Expected Scanner Results

When scanning this mock server, the MCP Security Scanner should detect:

### High-Severity Findings
- Command injection in `execute_command` tool
- SQL injection in `query_database` tool
- Path traversal in `read_file` tool
- Information disclosure in `/debug/info` endpoint

### Medium-Severity Findings
- XSS vulnerability in `generate_report` tool
- Insecure resource access patterns
- Sensitive data exposure in debug endpoints

### Low-Severity Findings
- Overly permissive CORS configuration
- Verbose error messages
- Missing security headers

## Development and Testing

### Adding New Vulnerabilities
1. Add new tool to `self.tools` array
2. Implement tool handler in `tool_*` method
3. Include intentional vulnerability
4. Document the vulnerability type and test case

### Testing Security Scanner
Use this mock server to test:
- Remote scanning capabilities
- MCP protocol handling
- Vulnerability detection accuracy
- False positive rates
- Performance under load

### Safe Mode Testing
Use `--safe` mode to test:
- MCP protocol compliance without vulnerabilities
- Scanner behavior with secure servers
- False positive detection

## Files

- `mock-mcp-server.py` - Main server implementation
- `test-mock-server.py` - Test script for server functionality
- `start-mock-server.sh` - Setup and start script
- `requirements.txt` - Python dependencies
- `MOCK_SERVER_README.md` - This documentation

## Troubleshooting

### Server Won't Start
- Check if port 8000 is available: `lsof -i :8000`
- Install dependencies: `pip3 install -r requirements.txt`
- Check Python version: `python3 --version` (requires 3.7+)

### Scanner Can't Connect
- Verify server is running: `curl http://localhost:8000/health`
- Check firewall settings
- Ensure correct URL in scanner command

### Missing Vulnerabilities
- Confirm server is in vulnerable mode (not `--safe`)
- Check server logs for error messages
- Verify tool names match expected patterns

## Contributing

To add new vulnerabilities or improve the mock server:

1. Follow the existing vulnerability patterns
2. Document the vulnerability type and test method
3. Ensure safe mode properly disables the vulnerability
4. Add corresponding test cases
5. Update this documentation

## License

This mock server is part of the MCP Security Scanner project and is intended for security testing purposes only.
