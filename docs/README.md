# MCP Security Scanner Documentation

This directory contains  documentation for the MCP Security Scanner project. The documentation is organised by functionality and target audience.

## Documentation Structure

### User Guides
- [**Installation Guide**](installation.md) - Setup, configuration, and initial deployment
- [**User Manual**](user-manual.md) - Complete guide to using the scanner and proxy
- [**Configuration Reference**](configuration.md) - Detailed configuration options and examples
- [**Configuration Management**](configuration-management.md) - YAML configuration system with environment variables

### Technical Documentation
- [**Architecture Overview**](architecture.md) - System design and component relationships
- [**Scanner Engine**](scanner-engine.md) - Core vulnerability detection logic and algorithms
- [**Proxy System**](proxy-documentation.md) - Real-time traffic analysis and interception
- [**Proxy API Reference**](proxy-api.md) - REST API endpoints for monitoring and integration
- [**Reporting System**](reporting-system.md) - Multi-format report generation and integration
- [**Polymorphic Patterns**](polymorphic-patterns.md) - Advanced detection patterns and techniques
- [**Pattern Configuration**](advanced-pattern-configuration.md) - Advanced weighted patterns, caching, and performance optimization (v1.2.0+)

### Security Operations
- [**Security Runbook**](security-runbook.md) - Operational procedures for security monitoring and response
- [**Incident Response Guide**](incident-response.md) - Step-by-step incident handling procedures
- [**Threat Model**](threat-model.md) - Security threat analysis and mitigation strategies
- [**Integration Guide**](integration-guide.md) - Enterprise SIEM, SOAR, and Slack integration configuration

### Testing & Quality Assurance
- [**Testing Guide**](testing-guide.md) - Live monitoring proxy test procedures, pattern performance testing, and validation methods
- [**Testing Infrastructure**](testing-infrastructure.md) - Comprehensive testing framework, unit tests, integration tests, and benchmarks

### Reference Materials
- [**Threat Model**](threat-model.md) - MCP-specific threats and attack vectors
### Reference Materials
- [**Policy Examples**](policy-examples.md) - Sample security policies and pattern configurations
- [**Troubleshooting Guide**](troubleshooting.md) - Common issues, solutions, and diagnostic procedures
- [**Custom Policies Guide**](custom-policies-guide.md) - Creating organisation-specific security policies
- [**Advanced Traffic Analysis**](advanced-traffic-analysis.md) - Deep packet inspection techniques and methodologies
- [**Polymorphic Enhancement Summary**](POLYMORPHIC_ENHANCEMENT_SUMMARY.md) - Detailed implementation summary of v1.2.0 enhancements

## Quick Navigation

### Getting Started
1. [Installation Guide](installation.md) - First-time setup
2. [User Manual](user-manual.md) - Basic operations
3. [Configuration Reference](configuration.md) - Customisation options

### For Developers
1. [Architecture Overview](architecture.md) - Understanding the codebase
2. [Scanner Engine](scanner-engine.md) - Core scanning logic
3. [Testing Infrastructure](testing-infrastructure.md) - Complete testing framework
4. [Testing Guide](testing-guide.md) - Live proxy testing procedures

### For Security Teams
1. [Polymorphic Patterns](polymorphic-patterns.md) - Advanced detection techniques
2. [Threat Model](threat-model.md) - MCP security considerations
3. [Policy Examples](policy-examples.md) - Security policy customisation

### For System Administrators
1. [Installation Guide](installation.md) - Deployment procedures
2. [Proxy System](proxy-documentation.md) - Traffic analysis and monitoring
3. [Troubleshooting](troubleshooting.md) - Problem resolution

## Documentation Conventions

- All paths referenced in documentation use forward slashes (/)
- Commands are shown for Unix-like systems (Linux/macOS)
- Configuration examples use YAML format unless otherwise specified
- Code examples include both Go and shell script snippets
- Security recommendations follow industry best practices

## Contributing to Documentation

When updating documentation:
1. Follow Australian English spelling conventions
2. Use clear, concise language without excessive jargon
3. Include practical examples and code snippets
4. Update this index when adding new documentation files
5. Test all commands and configurations before documenting

## Version Information

This documentation corresponds to MCP Security Scanner version 1.0.0 and MCP protocol version 2024-11-05.
