// Copyright (c) 2025 Gareth Phillips/syphon1c
// Licensed under the MIT License - see LICENSE file for details

package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Logger provides structured logging capabilities for the MCP Security Scanner
type Logger struct {
	level      LogLevel
	output     io.Writer
	logger     *log.Logger
	enableFile bool
	component  string
}

// Config holds configuration for the logger
type Config struct {
	Level      string `json:"level" yaml:"level"`
	Output     string `json:"output" yaml:"output"`
	EnableFile bool   `json:"enableFile" yaml:"enableFile"`
	Component  string `json:"component" yaml:"component"`
}

// NewLogger creates a new logger instance with the specified configuration
func NewLogger(config Config) (*Logger, error) {
	level, err := parseLogLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	var output io.Writer = os.Stdout
	if config.Output != "" && config.Output != "stdout" {
		dir := filepath.Dir(config.Output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		output = file
	}

	logger := log.New(output, "", 0)

	return &Logger{
		level:      level,
		output:     output,
		logger:     logger,
		enableFile: config.EnableFile,
		component:  config.Component,
	}, nil
}

// NewDefaultLogger creates a logger with default settings
func NewDefaultLogger(component string) *Logger {
	return &Logger{
		level:      INFO,
		output:     os.Stdout,
		logger:     log.New(os.Stdout, "", 0),
		enableFile: false,
		component:  component,
	}
}

// parseLogLevel converts a string to LogLevel
func parseLogLevel(level string) (LogLevel, error) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return DEBUG, nil
	case "INFO":
		return INFO, nil
	case "WARN", "WARNING":
		return WARN, nil
	case "ERROR":
		return ERROR, nil
	case "FATAL":
		return FATAL, nil
	default:
		return INFO, fmt.Errorf("unknown log level: %s", level)
	}
}

// log writes a log message with the specified level
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	var fileInfo string
	if l.enableFile {
		_, file, line, ok := runtime.Caller(3)
		if ok {
			fileInfo = fmt.Sprintf(" [%s:%d]", filepath.Base(file), line)
		}
	}

	component := ""
	if l.component != "" {
		component = fmt.Sprintf("[%s] ", l.component)
	}

	logLine := fmt.Sprintf("%s %s %s%s%s", timestamp, level.String(), component, message, fileInfo)
	l.logger.Println(logLine)

	if level == FATAL {
		os.Exit(1)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Fatal logs a fatal message and exits the program
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(FATAL, format, args...)
}

// SetLevel changes the logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// GetLevel returns the current logging level
func (l *Logger) GetLevel() LogLevel {
	return l.level
}

// WithComponent creates a new logger with the specified component name
func (l *Logger) WithComponent(component string) *Logger {
	newLogger := *l
	newLogger.component = component
	return &newLogger
}
