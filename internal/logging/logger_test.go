package logging

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogLevel_String(t *testing.T) {
	tests := []struct {
		name     string
		level    LogLevel
		expected string
	}{
		{
			name:     "DEBUG",
			level:    DEBUG,
			expected: "DEBUG",
		},
		{
			name:     "INFO",
			level:    INFO,
			expected: "INFO",
		},
		{
			name:     "WARN",
			level:    WARN,
			expected: "WARN",
		},
		{
			name:     "ERROR",
			level:    ERROR,
			expected: "ERROR",
		},
		{
			name:     "FATAL",
			level:    FATAL,
			expected: "FATAL",
		},
		{
			name:     "Unknown",
			level:    LogLevel(999),
			expected: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("LogLevel.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  LogLevel
		expectErr bool
	}{
		{
			name:      "DEBUG",
			input:     "DEBUG",
			expected:  DEBUG,
			expectErr: false,
		},
		{
			name:      "debug lowercase",
			input:     "debug",
			expected:  DEBUG,
			expectErr: false,
		},
		{
			name:      "INFO",
			input:     "INFO",
			expected:  INFO,
			expectErr: false,
		},
		{
			name:      "WARN",
			input:     "WARN",
			expected:  WARN,
			expectErr: false,
		},
		{
			name:      "WARNING",
			input:     "WARNING",
			expected:  WARN,
			expectErr: false,
		},
		{
			name:      "ERROR",
			input:     "ERROR",
			expected:  ERROR,
			expectErr: false,
		},
		{
			name:      "FATAL",
			input:     "FATAL",
			expected:  FATAL,
			expectErr: false,
		},
		{
			name:      "Invalid level",
			input:     "INVALID",
			expected:  INFO,
			expectErr: true,
		},
		{
			name:      "Empty string",
			input:     "",
			expected:  INFO,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLogLevel(tt.input)
			if (err != nil) != tt.expectErr {
				t.Errorf("parseLogLevel() error = %v, expectErr %v", err, tt.expectErr)
				return
			}
			if got != tt.expected {
				t.Errorf("parseLogLevel() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewDefaultLogger(t *testing.T) {
	component := "test-component"
	logger := NewDefaultLogger(component)

	if logger == nil {
		t.Fatal("NewDefaultLogger() should not return nil")
	}

	if logger.level != INFO {
		t.Errorf("NewDefaultLogger() level = %v, want %v", logger.level, INFO)
	}

	if logger.component != component {
		t.Errorf("NewDefaultLogger() component = %v, want %v", logger.component, component)
	}

	if logger.enableFile {
		t.Error("NewDefaultLogger() should not enable file logging by default")
	}

	if logger.output != os.Stdout {
		t.Error("NewDefaultLogger() should use stdout by default")
	}
}

func TestNewLogger_ValidConfig(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	config := Config{
		Level:      "DEBUG",
		Output:     logFile,
		EnableFile: true,
		Component:  "test-component",
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("NewLogger() unexpected error = %v", err)
	}

	if logger == nil {
		t.Fatal("NewLogger() should not return nil")
	}

	if logger.level != DEBUG {
		t.Errorf("NewLogger() level = %v, want %v", logger.level, DEBUG)
	}

	if logger.component != "test-component" {
		t.Errorf("NewLogger() component = %v, want %v", logger.component, "test-component")
	}

	if !logger.enableFile {
		t.Error("NewLogger() should enable file logging when configured")
	}
}

func TestNewLogger_InvalidLogLevel(t *testing.T) {
	config := Config{
		Level:     "INVALID",
		Component: "test",
	}

	logger, err := NewLogger(config)
	if err == nil {
		t.Error("NewLogger() should return error for invalid log level")
	}

	if logger != nil {
		t.Error("NewLogger() should return nil logger on error")
	}
}

func TestNewLogger_InvalidOutputFile(t *testing.T) {
	config := Config{
		Level:     "INFO",
		Output:    "/invalid/path/that/does/not/exist/test.log",
		Component: "test",
	}

	logger, err := NewLogger(config)
	if err == nil {
		t.Error("NewLogger() should return error for invalid output path")
	}

	if logger != nil {
		t.Error("NewLogger() should return nil logger on error")
	}
}

func TestNewLogger_StdoutOutput(t *testing.T) {
	config := Config{
		Level:     "INFO",
		Output:    "stdout",
		Component: "test",
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Fatalf("NewLogger() unexpected error = %v", err)
	}

	if logger.output != os.Stdout {
		t.Error("NewLogger() should use stdout when configured")
	}
}

func TestLogger_SetLevel(t *testing.T) {
	logger := NewDefaultLogger("test")

	logger.SetLevel(DEBUG)
	if logger.GetLevel() != DEBUG {
		t.Errorf("SetLevel(DEBUG) failed, got %v", logger.GetLevel())
	}

	logger.SetLevel(ERROR)
	if logger.GetLevel() != ERROR {
		t.Errorf("SetLevel(ERROR) failed, got %v", logger.GetLevel())
	}
}

func TestLogger_GetLevel(t *testing.T) {
	logger := NewDefaultLogger("test")

	if logger.GetLevel() != INFO {
		t.Errorf("GetLevel() = %v, want %v", logger.GetLevel(), INFO)
	}
}

func TestLogger_WithComponent(t *testing.T) {
	logger := NewDefaultLogger("original")
	newLogger := logger.WithComponent("new-component")

	if newLogger == logger {
		t.Error("WithComponent() should return a new logger instance")
	}

	if newLogger.component != "new-component" {
		t.Errorf("WithComponent() component = %v, want %v", newLogger.component, "new-component")
	}

	// Original logger should not be modified
	if logger.component != "original" {
		t.Error("WithComponent() should not modify original logger")
	}
}

func TestLogger_LogLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:      DEBUG,
		output:     &buf,
		logger:     log.New(&buf, "", 0),
		enableFile: false,
		component:  "test",
	}

	tests := []struct {
		name      string
		logFunc   func(string, ...interface{})
		level     LogLevel
		message   string
		args      []interface{}
		shouldLog bool
	}{
		{
			name:      "Debug message",
			logFunc:   logger.Debug,
			level:     DEBUG,
			message:   "debug message: %s",
			args:      []interface{}{"test"},
			shouldLog: true,
		},
		{
			name:      "Info message",
			logFunc:   logger.Info,
			level:     INFO,
			message:   "info message: %s",
			args:      []interface{}{"test"},
			shouldLog: true,
		},
		{
			name:      "Warn message",
			logFunc:   logger.Warn,
			level:     WARN,
			message:   "warn message: %s",
			args:      []interface{}{"test"},
			shouldLog: true,
		},
		{
			name:      "Error message",
			logFunc:   logger.Error,
			level:     ERROR,
			message:   "error message: %s",
			args:      []interface{}{"test"},
			shouldLog: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc(tt.message, tt.args...)

			output := buf.String()
			if tt.shouldLog {
				if output == "" {
					t.Error("Expected log output but got empty string")
				}
				if !strings.Contains(output, tt.level.String()) {
					t.Errorf("Expected output to contain %s, got: %s", tt.level.String(), output)
				}
				if !strings.Contains(output, "[test]") {
					t.Errorf("Expected output to contain component name, got: %s", output)
				}
			} else {
				if output != "" {
					t.Errorf("Expected no output but got: %s", output)
				}
			}
		})
	}
}

func TestLogger_LogLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:      WARN,
		output:     &buf,
		logger:     log.New(&buf, "", 0),
		enableFile: false,
		component:  "test",
	}

	// Debug and Info should be filtered out
	logger.Debug("debug message")
	logger.Info("info message")

	debugOutput := buf.String()
	if debugOutput != "" {
		t.Errorf("Debug and Info messages should be filtered out, got: %s", debugOutput)
	}

	// Warn and Error should pass through
	logger.Warn("warn message")
	logger.Error("error message")

	warnErrorOutput := buf.String()
	if warnErrorOutput == "" {
		t.Error("Warn and Error messages should not be filtered out")
	}
	if !strings.Contains(warnErrorOutput, "WARN") {
		t.Error("Output should contain WARN level")
	}
	if !strings.Contains(warnErrorOutput, "ERROR") {
		t.Error("Output should contain ERROR level")
	}
}

func TestLogger_FileInfoEnabled(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:      INFO,
		output:     &buf,
		logger:     log.New(&buf, "", 0),
		enableFile: true,
		component:  "test",
	}

	logger.Info("test message")

	output := buf.String()
	// Check that file info is present in some form (could be .go file extension)
	if !strings.Contains(output, ".go:") {
		t.Errorf("Expected output to contain file info, got: %s", output)
	}
}

func TestLogger_FileInfoDisabled(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:      INFO,
		output:     &buf,
		logger:     log.New(&buf, "", 0),
		enableFile: false,
		component:  "test",
	}

	logger.Info("test message")

	output := buf.String()
	// When file info is disabled, should not contain file info pattern
	if strings.Contains(output, ".go:") {
		t.Errorf("Expected output to not contain file info, got: %s", output)
	}
}

func TestLogger_EmptyComponent(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		level:      INFO,
		output:     &buf,
		logger:     log.New(&buf, "", 0),
		enableFile: false,
		component:  "",
	}

	logger.Info("test message")

	output := buf.String()
	// Should not contain empty component brackets
	if strings.Contains(output, "[] ") {
		t.Errorf("Expected output to not contain empty component brackets, got: %s", output)
	}
}
