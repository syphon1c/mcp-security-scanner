package errors

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestErrorType_String(t *testing.T) {
	tests := []struct {
		name     string
		errType  ErrorType
		expected string
	}{
		{
			name:     "ConfigErrorType",
			errType:  ConfigErrorType,
			expected: "CONFIG_ERROR",
		},
		{
			name:     "NetworkErrorType",
			errType:  NetworkErrorType,
			expected: "NETWORK_ERROR",
		},
		{
			name:     "FileSystemErrorType",
			errType:  FileSystemErrorType,
			expected: "FILESYSTEM_ERROR",
		},
		{
			name:     "PolicyErrorType",
			errType:  PolicyErrorType,
			expected: "POLICY_ERROR",
		},
		{
			name:     "ScanErrorType",
			errType:  ScanErrorType,
			expected: "SCAN_ERROR",
		},
		{
			name:     "ReportErrorType",
			errType:  ReportErrorType,
			expected: "REPORT_ERROR",
		},
		{
			name:     "ValidationErrorType",
			errType:  ValidationErrorType,
			expected: "VALIDATION_ERROR",
		},
		{
			name:     "IntegrationErrorType",
			errType:  IntegrationErrorType,
			expected: "INTEGRATION_ERROR",
		},
		{
			name:     "InternalErrorType",
			errType:  InternalErrorType,
			expected: "INTERNAL_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.errType); got != tt.expected {
				t.Errorf("ErrorType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMCPError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *MCPError
		expected string
	}{
		{
			name: "ErrorWithoutOriginal",
			err: &MCPError{
				Type:    ConfigErrorType,
				Message: "test message",
			},
			expected: "CONFIG_ERROR: test message",
		},
		{
			name: "ErrorWithOriginal",
			err: &MCPError{
				Type:        NetworkErrorType,
				Message:     "network issue",
				OriginalErr: errors.New("connection refused"),
			},
			expected: "NETWORK_ERROR: network issue: connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("MCPError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMCPError_Unwrap(t *testing.T) {
	originalErr := errors.New("original error")
	mcpErr := &MCPError{
		Type:        ConfigErrorType,
		Message:     "test",
		OriginalErr: originalErr,
	}

	if got := mcpErr.Unwrap(); got != originalErr {
		t.Errorf("MCPError.Unwrap() = %v, want %v", got, originalErr)
	}

	// Test nil case
	mcpErrNil := &MCPError{
		Type:    ConfigErrorType,
		Message: "test",
	}

	if got := mcpErrNil.Unwrap(); got != nil {
		t.Errorf("MCPError.Unwrap() = %v, want nil", got)
	}
}

func TestMCPError_GetUserMessage(t *testing.T) {
	tests := []struct {
		name     string
		err      *MCPError
		expected string
	}{
		{
			name: "WithUserMessage",
			err: &MCPError{
				Message:     "technical message",
				UserMessage: "user-friendly message",
			},
			expected: "user-friendly message",
		},
		{
			name: "WithoutUserMessage",
			err: &MCPError{
				Message: "technical message",
			},
			expected: "technical message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.GetUserMessage(); got != tt.expected {
				t.Errorf("MCPError.GetUserMessage() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMCPError_AddContext(t *testing.T) {
	err := &MCPError{
		Type:    ConfigErrorType,
		Message: "test",
	}

	// Test adding context
	err.AddContext("key1", "value1")
	err.AddContext("key2", 123)

	if err.Context == nil {
		t.Fatal("Context should not be nil after adding context")
	}

	if got, ok := err.Context["key1"]; !ok || got != "value1" {
		t.Errorf("Context['key1'] = %v, want 'value1'", got)
	}

	if got, ok := err.Context["key2"]; !ok || got != 123 {
		t.Errorf("Context['key2'] = %v, want 123", got)
	}
}

func TestMCPError_GetContext(t *testing.T) {
	err := &MCPError{
		Type:    ConfigErrorType,
		Message: "test",
		Context: map[string]interface{}{
			"existing": "value",
		},
	}

	// Test getting existing context
	value, ok := err.GetContext("existing")
	if !ok {
		t.Error("Expected GetContext to return true for existing key")
	}
	if value != "value" {
		t.Errorf("GetContext('existing') = %v, want 'value'", value)
	}

	// Test getting non-existing context
	value, ok = err.GetContext("nonexistent")
	if ok {
		t.Error("Expected GetContext to return false for non-existing key")
	}
	if value != nil {
		t.Errorf("GetContext('nonexistent') = %v, want nil", value)
	}

	// Test nil context
	errNilContext := &MCPError{
		Type:    ConfigErrorType,
		Message: "test",
	}

	value, ok = errNilContext.GetContext("any")
	if ok {
		t.Error("Expected GetContext to return false for nil context")
	}
	if value != nil {
		t.Errorf("GetContext on nil context = %v, want nil", value)
	}
}

func TestNew(t *testing.T) {
	err := New(ConfigErrorType, "test message")

	if err.Type != ConfigErrorType {
		t.Errorf("New() Type = %v, want %v", err.Type, ConfigErrorType)
	}

	if err.Message != "test message" {
		t.Errorf("New() Message = %v, want %v", err.Message, "test message")
	}

	if err.Context == nil {
		t.Error("New() Context should not be nil")
	}

	if err.StackTrace == nil {
		t.Error("New() StackTrace should not be nil")
	}

	if !err.Recoverable {
		t.Error("New() should create recoverable error by default")
	}
}

func TestWrap(t *testing.T) {
	originalErr := errors.New("original error")
	err := Wrap(originalErr, NetworkErrorType, "wrapped message")

	if err.Type != NetworkErrorType {
		t.Errorf("Wrap() Type = %v, want %v", err.Type, NetworkErrorType)
	}

	if err.Message != "wrapped message" {
		t.Errorf("Wrap() Message = %v, want %v", err.Message, "wrapped message")
	}

	if err.OriginalErr != originalErr {
		t.Errorf("Wrap() OriginalErr = %v, want %v", err.OriginalErr, originalErr)
	}

	if err.Context == nil {
		t.Error("Wrap() Context should not be nil")
	}

	if err.StackTrace == nil {
		t.Error("Wrap() StackTrace should not be nil")
	}
}

func TestWrapf(t *testing.T) {
	originalErr := errors.New("original error")
	err := Wrapf(originalErr, NetworkErrorType, "wrapped message: %s", "test")

	if err.Type != NetworkErrorType {
		t.Errorf("Wrapf() Type = %v, want %v", err.Type, NetworkErrorType)
	}

	if err.Message != "wrapped message: test" {
		t.Errorf("Wrapf() Message = %v, want %v", err.Message, "wrapped message: test")
	}

	if err.OriginalErr != originalErr {
		t.Errorf("Wrapf() OriginalErr = %v, want %v", err.OriginalErr, originalErr)
	}
}

func TestSpecificErrorConstructors(t *testing.T) {
	tests := []struct {
		name         string
		constructor  func() *MCPError
		expectedType ErrorType
		checkContext func(*MCPError) error
	}{
		{
			name: "ConfigurationError",
			constructor: func() *MCPError {
				return ConfigurationError("config issue")
			},
			expectedType: ConfigErrorType,
			checkContext: func(err *MCPError) error {
				if !err.IsRecoverable() {
					return fmt.Errorf("ConfigurationError should be recoverable")
				}
				if !strings.Contains(err.GetUserMessage(), "Configuration error") {
					return fmt.Errorf("ConfigurationError should have user-friendly message")
				}
				return nil
			},
		},
		{
			name: "NetworkError",
			constructor: func() *MCPError {
				return NetworkError(errors.New("connection failed"), "network issue")
			},
			expectedType: NetworkErrorType,
			checkContext: func(err *MCPError) error {
				if !err.IsRecoverable() {
					return fmt.Errorf("NetworkError should be recoverable")
				}
				if !strings.Contains(err.GetUserMessage(), "Network error") {
					return fmt.Errorf("NetworkError should have user-friendly message")
				}
				return nil
			},
		},
		{
			name: "FileSystemError",
			constructor: func() *MCPError {
				return FileSystemError(errors.New("file not found"), "/test/path")
			},
			expectedType: FileSystemErrorType,
			checkContext: func(err *MCPError) error {
				if err.IsRecoverable() {
					return fmt.Errorf("FileSystemError should not be recoverable")
				}
				path, ok := err.GetContext("path")
				if !ok || path != "/test/path" {
					return fmt.Errorf("FileSystemError should have path context")
				}
				return nil
			},
		},
		{
			name: "PolicyError",
			constructor: func() *MCPError {
				return PolicyError("policy issue", "test-policy")
			},
			expectedType: PolicyErrorType,
			checkContext: func(err *MCPError) error {
				policy, ok := err.GetContext("policy")
				if !ok || policy != "test-policy" {
					return fmt.Errorf("PolicyError should have policy context")
				}
				return nil
			},
		},
		{
			name: "ScanError",
			constructor: func() *MCPError {
				return ScanError(errors.New("scan failed"), "target-server")
			},
			expectedType: ScanErrorType,
			checkContext: func(err *MCPError) error {
				target, ok := err.GetContext("target")
				if !ok || target != "target-server" {
					return fmt.Errorf("ScanError should have target context")
				}
				return nil
			},
		},
		{
			name: "ReportError",
			constructor: func() *MCPError {
				return ReportError(errors.New("report failed"), "PDF")
			},
			expectedType: ReportErrorType,
			checkContext: func(err *MCPError) error {
				format, ok := err.GetContext("format")
				if !ok || format != "PDF" {
					return fmt.Errorf("ReportError should have format context")
				}
				return nil
			},
		},
		{
			name: "ValidationError",
			constructor: func() *MCPError {
				return ValidationError("username", "")
			},
			expectedType: ValidationErrorType,
			checkContext: func(err *MCPError) error {
				field, ok := err.GetContext("field")
				if !ok || field != "username" {
					return fmt.Errorf("ValidationError should have field context")
				}
				value, ok := err.GetContext("value")
				if !ok || value != "" {
					return fmt.Errorf("ValidationError should have value context")
				}
				return nil
			},
		},
		{
			name: "IntegrationError",
			constructor: func() *MCPError {
				return IntegrationError(errors.New("connection failed"), "SIEM")
			},
			expectedType: IntegrationErrorType,
			checkContext: func(err *MCPError) error {
				service, ok := err.GetContext("service")
				if !ok || service != "SIEM" {
					return fmt.Errorf("IntegrationError should have service context")
				}
				return nil
			},
		},
		{
			name: "InternalError",
			constructor: func() *MCPError {
				return InternalError(errors.New("internal failure"), "database-operation")
			},
			expectedType: InternalErrorType,
			checkContext: func(err *MCPError) error {
				if err.IsRecoverable() {
					return fmt.Errorf("InternalError should not be recoverable")
				}
				operation, ok := err.GetContext("operation")
				if !ok || operation != "database-operation" {
					return fmt.Errorf("InternalError should have operation context")
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.constructor()

			if err.Type != tt.expectedType {
				t.Errorf("Constructor() Type = %v, want %v", err.Type, tt.expectedType)
			}

			if tt.checkContext != nil {
				if contextErr := tt.checkContext(err); contextErr != nil {
					t.Errorf("Context check failed: %v", contextErr)
				}
			}
		})
	}
}

func TestMCPError_SetUserMessage(t *testing.T) {
	err := New(ConfigErrorType, "technical message")
	result := err.SetUserMessage("user message")

	if result != err {
		t.Error("SetUserMessage should return the same error instance")
	}

	if err.UserMessage != "user message" {
		t.Errorf("SetUserMessage() UserMessage = %v, want %v", err.UserMessage, "user message")
	}
}

func TestMCPError_SetRecoverable(t *testing.T) {
	err := New(ConfigErrorType, "test")
	result := err.SetRecoverable(false)

	if result != err {
		t.Error("SetRecoverable should return the same error instance")
	}

	if err.Recoverable {
		t.Error("SetRecoverable(false) should set Recoverable to false")
	}

	err.SetRecoverable(true)
	if !err.Recoverable {
		t.Error("SetRecoverable(true) should set Recoverable to true")
	}
}

func TestMCPError_IsRecoverable(t *testing.T) {
	err := New(ConfigErrorType, "test")

	if !err.IsRecoverable() {
		t.Error("New error should be recoverable by default")
	}

	err.SetRecoverable(false)
	if err.IsRecoverable() {
		t.Error("IsRecoverable should return false after SetRecoverable(false)")
	}
}

func TestMCPError_GetStackTrace(t *testing.T) {
	err := New(ConfigErrorType, "test")
	stackTrace := err.GetStackTrace()

	if stackTrace == "" {
		t.Error("GetStackTrace should return non-empty string")
	}

	if !strings.Contains(stackTrace, "errors_test.go") {
		t.Error("Stack trace should contain test file name")
	}
}

func TestIsType(t *testing.T) {
	mcpErr := New(ConfigErrorType, "test")
	regularErr := errors.New("regular error")

	// Test with MCPError
	if !IsType(mcpErr, ConfigErrorType) {
		t.Error("IsType should return true for matching MCPError type")
	}

	if IsType(mcpErr, NetworkErrorType) {
		t.Error("IsType should return false for non-matching MCPError type")
	}

	// Test with regular error
	if IsType(regularErr, ConfigErrorType) {
		t.Error("IsType should return false for regular error")
	}

	// Test with nil
	if IsType(nil, ConfigErrorType) {
		t.Error("IsType should return false for nil error")
	}
}

func TestCaptureStackTrace(t *testing.T) {
	trace := captureStackTrace()

	if len(trace) == 0 {
		t.Error("captureStackTrace should return non-empty slice")
	}

	// Should contain at least one frame (may be from Go runtime or test framework)
	if len(trace) == 0 {
		t.Error("Stack trace should contain at least one frame")
	}
}
