# Troubleshooting Guide

This guide provides solutions to common issues encountered when using the MCP Security Scanner. Issues are organised by component and severity.

## Quick Diagnostics

### Health Check Commands

Before diving into specific issues, run these commands to check system health:

```bash
# Verify installation
./mcpscan version

# Test basic functionality
./mcpscan scan-local . standard-security --output-dir ./test-reports

# Check policies are available
./mcpscan policies

# Test proxy connectivity
./mcpscan proxy --test-mode localhost 8080
```

### Log Analysis

Enable debug logging for troubleshooting:

```bash
# Enable debug mode
export MCP_DEBUG=true
./mcpscan scan-local . critical-security --verbose

# Check log files
tail -f ./logs/mcpscan.log
```

## Scanner Issues

### Issue: Scanner Fails to Start

**Symptoms**:
- `mcpscan` command not found
- Permission denied errors
- Binary crashes on startup

**Solutions**:

1. **Verify Installation**:
   ```bash
   # Check if binary exists
   ls -la ./mcpscan
   
   # Check permissions
   chmod +x ./mcpscan
   
   # Verify Go installation
   go version
   ```

2. **Check Dependencies**:
   ```bash
   # Rebuild from source
   go mod tidy
   go build -o mcpscan
   ```

3. **Environment Issues**:
   ```bash
   # Check environment variables
   echo $PATH
   echo $GOPATH
   
   # Reset environment if needed
   export PATH=$PATH:/usr/local/go/bin
   ```

### Issue: Policy Loading Failures

**Symptoms**:
- "Policy not found" errors
- Empty scan results
- Policy validation failures

**Solutions**:

1. **Verify Policy Files**:
   ```bash
   # Check policy directory
   ls -la ./policies/
   
   # Validate JSON syntax
   python -m json.tool ./policies/critical-security.json
   ```

2. **Policy Path Issues**:
   ```bash
   # Use absolute paths
   ./mcpscan scan-local . /full/path/to/policies/critical-security.json
   
   # Check current directory
   pwd
   ```

3. **Policy Format Validation**:
   ```json
   {
     "policyName": "must-match-filename",
     "version": "1.0",
     "rules": [...],
     "riskThresholds": {...}
   }
   ```

### Issue: Slow Scanning Performance

**Symptoms**:
- Scans take excessive time
- High CPU usage
- Memory consumption issues

**Solutions**:

1. **Optimise Scan Scope**:
   ```bash
   # Exclude unnecessary directories
   ./mcpscan scan-local ./src critical-security --exclude="node_modules,*.log"
   
   # Use specific file patterns
   ./mcpscan scan-local . critical-security --include="*.go,*.py"
   ```

2. **Adjust Policy Complexity**:
   - Simplify regex patterns in policies
   - Reduce number of rules for initial scans
   - Use more specific patterns

3. **System Resources**:
   ```bash
   # Monitor resource usage
   top -p $(pgrep mcpscan)
   
   # Increase available memory
   ulimit -m 4194304  # 4GB limit
   ```

### Issue: False Positive Results

**Symptoms**:
- Legitimate code flagged as vulnerable
- Excessive low-severity findings
- Context-inappropriate detections

**Solutions**:

1. **Tune Policy Rules**:
   - Adjust pattern specificity
   - Increase risk thresholds
   - Add context-aware rules

2. **Use Exclusion Patterns**:
   ```json
   {
     "rules": [{
       "id": "INJECTION_001",
       "patterns": ["exec\\s*\\("],
       "excludePatterns": ["# Safe usage:", "test_exec"]
     }]
   }
   ```

3. **Custom Policy Creation**:
   - Create organisation-specific policies
   - Baseline against known-good code
   - Regular policy refinement

## Proxy Issues

### Issue: Proxy Connection Failures

**Symptoms**:
- Cannot connect to target server
- Connection timeouts
- TLS/SSL errors

**Solutions**:

1. **Network Connectivity**:
   ```bash
   # Test target connectivity
   curl -I https://target-server.com
   telnet target-server.com 443
   
   # Check DNS resolution
   nslookup target-server.com
   ```

2. **TLS Configuration**:
   ```bash
   # Test TLS connection
   openssl s_client -connect target-server.com:443
   
   # Disable TLS verification for testing
   ./mcpscan proxy https://target-server.com 8080 --insecure
   ```

3. **Firewall and Network**:
   ```bash
   # Check firewall rules
   sudo iptables -L
   
   # Test port availability
   netstat -tuln | grep 8080
   ```

### Issue: WebSocket Proxy Problems

**Symptoms**:
- WebSocket upgrade failures
- Message corruption
- Connection drops

**Solutions**:

1. **Protocol Verification**:
   ```bash
   # Test WebSocket connection
   wscat -c ws://localhost:8080
   
   # Check upgrade headers
   curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
        -H "Sec-WebSocket-Key: test" -H "Sec-WebSocket-Version: 13" \
        http://localhost:8080
   ```

2. **Proxy Configuration**:
   ```yaml
   proxy:
     websocket:
       enabled: true
       bufferSize: 4096
       compression: false
   ```

3. **Message Handling**:
   - Increase buffer sizes
   - Disable compression for debugging
   - Check message framing

### Issue: High Proxy Latency

**Symptoms**:
- Slow response times
- Connection timeouts
- Performance degradation

**Solutions**:

1. **Performance Tuning**:
   ```yaml
   proxy:
     performance:
       bufferSize: 8192
       maxConnections: 1000
       keepAlive: true
   ```

2. **Resource Monitoring**:
   ```bash
   # Monitor proxy performance
   top -p $(pgrep mcpscan)
   iotop -p $(pgrep mcpscan)
   ```

3. **Network Optimisation**:
   - Use local network interfaces
   - Optimise TCP settings
   - Consider hardware acceleration

## Configuration Issues

### Issue: Configuration File Problems

**Symptoms**:
- Configuration not loaded
- Invalid configuration errors
- Default values not applied

**Solutions**:

1. **File Location**:
   ```bash
   # Check default locations
   ls ./configs/config.yaml
   ls ~/.mcpscan/config.yaml
   ls /etc/mcpscan/config.yaml
   ```

2. **YAML Syntax Validation**:
   ```bash
   # Validate YAML syntax
   python -c "import yaml; yaml.safe_load(open('./configs/config.yaml'))"
   
   # Check indentation
   cat -A ./configs/config.yaml
   ```

3. **Configuration Override**:
   ```bash
   # Specify config file explicitly
   ./mcpscan --config ./custom-config.yaml scan-local . critical-security
   
   # Use environment variables
   export MCP_CONFIG_FILE=./configs/config.yaml
   ```

### Issue: Integration Configuration

**Symptoms**:
- SIEM integration failures
- Webhook delivery issues
- Authentication problems

**Solutions**:

1. **Endpoint Testing**:
   ```bash
   # Test SIEM endpoint
   curl -X POST https://siem-endpoint.com/api/alerts \
        -H "Content-Type: application/json" \
        -d '{"test": "message"}'
   
   # Verify webhook URL
   curl -X POST https://hooks.slack.com/services/... \
        -d '{"text": "Test message"}'
   ```

2. **Authentication Verification**:
   ```yaml
   integration:
     siem:
       endpoint: "https://siem.company.com/api"
       apiKey: "your-api-key"
       timeout: 30
   ```

3. **Network Access**:
   - Check firewall rules for outbound connections
   - Verify DNS resolution for integration endpoints
   - Test connectivity from scanning environment

## Report Generation Issues

### Issue: Report Generation Failures

**Symptoms**:
- Empty report files
- Format conversion errors
- File permission issues

**Solutions**:

1. **Directory Permissions**:
   ```bash
   # Check output directory
   ls -la ./reports/
   
   # Create directory if missing
   mkdir -p ./reports/
   chmod 755 ./reports/
   ```

2. **Format-Specific Issues**:
   ```bash
   # Test different formats
   ./mcpscan scan-local . critical-security --format json
   ./mcpscan scan-local . critical-security --format html
   ./mcpscan scan-local . critical-security --format text
   ```

3. **Template Issues**:
   ```bash
   # Check template files
   ls -la ./templates/
   
   # Validate template syntax
   go run -c 'package main; import "text/template"; template.Must(template.ParseFiles("./templates/report.html"))'
   ```

### Issue: PDF Generation Problems

**Symptoms**:
- PDF files corrupted or empty
- Font rendering issues
- Layout problems

**Solutions**:

1. **Pure Go Implementation**:
   ```bash
   # No external dependencies required
   ./mcpscan scan-local . critical-security --output-format pdf
   ```

2. **Alternative PDF Generation**:
   ```bash
   # Generate HTML first, then use browser print-to-PDF
   ./mcpscan scan-local . critical-security --format html
   # Open HTML file in browser and print to PDF
   ```

3. **Font Configuration** (if text rendering issues):
   ```bash
   # Check available fonts (Linux)
   fc-list
   
   # Install additional fonts if needed (Linux)
   sudo apt-get install fonts-liberation
   ```

## Performance Optimisation

### Memory Usage Optimisation

```bash
# Monitor memory usage
ps aux | grep mcpscan

# Increase Go garbage collection
export GOGC=50

# Limit memory usage
ulimit -v 4194304  # 4GB virtual memory limit
```

### CPU Usage Optimisation

```bash
# Limit CPU usage
cpulimit -l 50 -p $(pgrep mcpscan)

# Use multiple cores efficiently
export GOMAXPROCS=4
```

### Disk I/O Optimisation

```bash
# Use SSD storage for temporary files
export TMPDIR=/path/to/ssd/tmp

# Monitor disk usage
iotop -p $(pgrep mcpscan)
```

## Debugging Tips

### Enable Verbose Logging

```bash
# Maximum verbosity
./mcpscan --verbose --debug scan-local . critical-security

# Log to file
./mcpscan scan-local . critical-security 2>&1 | tee scan.log
```

### Network Debugging

```bash
# Capture network traffic
sudo tcpdump -i any -w mcpscan.pcap host target-server.com

# Monitor connections
netstat -an | grep mcpscan
```

### Memory Debugging

```bash
# Check for memory leaks
valgrind --tool=memcheck ./mcpscan scan-local . critical-security

# Go memory profiling
go tool pprof http://localhost:6060/debug/pprof/heap
```

## Getting Help

### Log Information to Collect

When reporting issues, include:

1. **Version Information**:
   ```bash
   ./mcpscan version
   go version
   uname -a
   ```

2. **Configuration**:
   ```bash
   # Sanitised configuration (remove secrets)
   cat ./configs/config.yaml | sed 's/apiKey:.*/apiKey: [REDACTED]/'
   ```

3. **Error Messages**:
   ```bash
   # Full error output
   ./mcpscan scan-local . critical-security --verbose 2>&1
   ```

4. **System Information**:
   ```bash
   # Resource usage
   free -h
   df -h
   top -n 1
   ```

### Support Channels

- GitHub Issues: Report bugs and feature requests
- Documentation: Check latest documentation updates
- Community Forum: Discuss best practices and configurations

### Emergency Procedures

For critical security incidents:

1. Stop affected services immediately
2. Preserve logs and evidence
3. Contact security team
4. Follow incident response procedures
5. Update security policies based on lessons learned

## Related Documentation

- [Configuration Reference](configuration.md) - Detailed configuration options
- [User Manual](user-manual.md) - Complete usage guide
- [Scanner Engine](scanner-engine.md) - Technical implementation details
- [Proxy Documentation](proxy-documentation.md) - Proxy system details
