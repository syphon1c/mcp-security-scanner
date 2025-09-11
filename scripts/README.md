# MCP Security Scanner - Utility Scripts

This directory contains standalone Go programs for testing and development purposes.

## Available Scripts

### `test_pattern_caching.go`
Basic functionality test script that verifies the scanner's core capabilities:
- Tests policy loading and validation
- Creates temporary vulnerable code samples
- Scans with different security policies
- Reports findings and risk scores

**Usage:**
```bash
go run test_pattern_caching.go
```

### `test_pattern_caching_perf.go`
Performance testing script that measures pattern compilation caching effectiveness:
- Tests regex pattern compilation caching
- Measures performance difference between cold and warm cache
- Reports performance improvements from caching
- Validates consistency across multiple scans

**Usage:**
```bash
go run test_pattern_caching_perf.go
```

## Important Notes

These scripts are **standalone programs** and are excluded from the main Go module build process to avoid conflicts with the main application. They each have their own `main()` function and can be run independently for testing and development purposes.

The scripts automatically:
- Load the scanner's configuration
- Create temporary test files with vulnerable code
- Clean up after themselves
- Provide detailed output about their operations

These are development tools and are not part of the production MCP Security Scanner binary.
