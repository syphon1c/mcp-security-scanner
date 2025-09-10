// Copyright (c) 2025 Gareth Phillips/syphon1c
// Licensed under the MIT License - see LICENSE file for details

package errors

import (
	"fmt"
	"runtime"
	"strings"
)

// ErrorType represents different categories of errors
type ErrorType string

const (
	ConfigErrorType      ErrorType = "CONFIG_ERROR"
	NetworkErrorType     ErrorType = "NETWORK_ERROR"
	FileSystemErrorType  ErrorType = "FILESYSTEM_ERROR"
	PolicyErrorType      ErrorType = "POLICY_ERROR"
	ScanErrorType        ErrorType = "SCAN_ERROR"
	ReportErrorType      ErrorType = "REPORT_ERROR"
	ValidationErrorType  ErrorType = "VALIDATION_ERROR"
	IntegrationErrorType ErrorType = "INTEGRATION_ERROR"
	InternalErrorType    ErrorType = "INTERNAL_ERROR"
)

// MCPError represents an error with context and categorisation
type MCPError struct {
	Type        ErrorType
	Message     string
	OriginalErr error
	Context     map[string]interface{}
	StackTrace  []string
	UserMessage string
	Recoverable bool
}

// Error implements the error interface
func (e *MCPError) Error() string {
	if e.OriginalErr != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.OriginalErr)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the original error for error unwrapping
func (e *MCPError) Unwrap() error {
	return e.OriginalErr
}

// GetUserMessage returns a user-friendly error message
func (e *MCPError) GetUserMessage() string {
	if e.UserMessage != "" {
		return e.UserMessage
	}
	return e.Message
}

// AddContext adds contextual information to the error
func (e *MCPError) AddContext(key string, value interface{}) *MCPError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// GetContext retrieves contextual information from the error
func (e *MCPError) GetContext(key string) (interface{}, bool) {
	if e.Context == nil {
		return nil, false
	}
	val, ok := e.Context[key]
	return val, ok
}

// New creates a new MCPError with the specified type and message
func New(errType ErrorType, message string) *MCPError {
	return &MCPError{
		Type:        errType,
		Message:     message,
		Context:     make(map[string]interface{}),
		StackTrace:  captureStackTrace(),
		Recoverable: true,
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, errType ErrorType, message string) *MCPError {
	return &MCPError{
		Type:        errType,
		Message:     message,
		OriginalErr: err,
		Context:     make(map[string]interface{}),
		StackTrace:  captureStackTrace(),
		Recoverable: true,
	}
}

// Wrapf wraps an existing error with a formatted message
func Wrapf(err error, errType ErrorType, format string, args ...interface{}) *MCPError {
	return Wrap(err, errType, fmt.Sprintf(format, args...))
}

// captureStackTrace captures the current stack trace
func captureStackTrace() []string {
	var trace []string
	pc := make([]uintptr, 10)
	n := runtime.Callers(3, pc) // Skip 3 frames to get to the actual caller

	frames := runtime.CallersFrames(pc[:n])
	for {
		frame, more := frames.Next()
		if !strings.Contains(frame.File, "runtime/") {
			trace = append(trace, fmt.Sprintf("%s:%d %s", frame.File, frame.Line, frame.Function))
		}
		if !more {
			break
		}
	}
	return trace
}

// ConfigurationError creates a configuration-related error
func ConfigurationError(message string) *MCPError {
	return New(ConfigErrorType, message).
		SetUserMessage("Configuration error: Please check your configuration file and try again").
		SetRecoverable(true)
}

// NetworkError creates a network-related error
func NetworkError(err error, message string) *MCPError {
	return Wrap(err, NetworkErrorType, message).
		SetUserMessage("Network error: Please check your connection and try again").
		SetRecoverable(true)
}

// FileSystemError creates a filesystem-related error
func FileSystemError(err error, path string) *MCPError {
	return Wrap(err, FileSystemErrorType, fmt.Sprintf("filesystem operation failed on: %s", path)).
		AddContext("path", path).
		SetUserMessage(fmt.Sprintf("File system error: Unable to access %s", path)).
		SetRecoverable(false)
}

// PolicyError creates a policy-related error
func PolicyError(message string, policy string) *MCPError {
	return New(PolicyErrorType, message).
		AddContext("policy", policy).
		SetUserMessage(fmt.Sprintf("Policy error: Issue with policy '%s'", policy)).
		SetRecoverable(true)
}

// ScanError creates a scan-related error
func ScanError(err error, target string) *MCPError {
	return Wrap(err, ScanErrorType, fmt.Sprintf("scan failed for target: %s", target)).
		AddContext("target", target).
		SetUserMessage(fmt.Sprintf("Scan error: Unable to scan target '%s'", target)).
		SetRecoverable(true)
}

// ReportError creates a report generation error
func ReportError(err error, format string) *MCPError {
	return Wrap(err, ReportErrorType, fmt.Sprintf("report generation failed for format: %s", format)).
		AddContext("format", format).
		SetUserMessage(fmt.Sprintf("Report error: Unable to generate %s report", format)).
		SetRecoverable(true)
}

// ValidationError creates a validation error
func ValidationError(field string, value interface{}) *MCPError {
	return New(ValidationErrorType, fmt.Sprintf("validation failed for field: %s", field)).
		AddContext("field", field).
		AddContext("value", value).
		SetUserMessage(fmt.Sprintf("Validation error: Invalid value for %s", field)).
		SetRecoverable(true)
}

// IntegrationError creates an integration-related error
func IntegrationError(err error, service string) *MCPError {
	return Wrap(err, IntegrationErrorType, fmt.Sprintf("integration failed with service: %s", service)).
		AddContext("service", service).
		SetUserMessage(fmt.Sprintf("Integration error: Unable to connect to %s", service)).
		SetRecoverable(true)
}

// InternalError creates an internal system error
func InternalError(err error, operation string) *MCPError {
	return Wrap(err, InternalErrorType, fmt.Sprintf("internal error during: %s", operation)).
		AddContext("operation", operation).
		SetUserMessage("Internal error: Please contact support if this persists").
		SetRecoverable(false)
}

// SetUserMessage sets a user-friendly error message
func (e *MCPError) SetUserMessage(message string) *MCPError {
	e.UserMessage = message
	return e
}

// SetRecoverable sets whether the error is recoverable
func (e *MCPError) SetRecoverable(recoverable bool) *MCPError {
	e.Recoverable = recoverable
	return e
}

// IsRecoverable returns whether the error is recoverable
func (e *MCPError) IsRecoverable() bool {
	return e.Recoverable
}

// GetStackTrace returns the stack trace as a string
func (e *MCPError) GetStackTrace() string {
	return strings.Join(e.StackTrace, "\n")
}

// IsType checks if the error is of a specific type
func IsType(err error, errType ErrorType) bool {
	if mcpErr, ok := err.(*MCPError); ok {
		return mcpErr.Type == errType
	}
	return false
}
