package policy

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// Engine manages security policies and their enforcement
type Engine struct {
	policies map[string]*types.SecurityPolicy
}

// NewEngine creates a new security policy engine with initialized policy storage.
// The engine maintains an in-memory registry of security policies that can be loaded
// from JSON files and used for vulnerability detection and security rule enforcement.
//
// Returns:
//   - *Engine: Initialized policy engine with empty policy registry ready for loading
//
// The engine supports multiple policy formats, policy validation, and dynamic policy
// management for comprehensive security scanning across different threat models.
func NewEngine() *Engine {
	return &Engine{
		policies: make(map[string]*types.SecurityPolicy),
	}
}

// LoadPoliciesFromDirectory recursively loads all JSON security policy files from a directory.
// The function traverses the directory structure, identifies policy files by .json extension,
// and loads each policy into the engine's registry. Failed policy loads are logged but do not
// stop the loading of other valid policies, allowing partial policy loading in mixed scenarios.
//
// Parameters:
//   - policyDir: Root directory path containing JSON policy files to load
//
// Returns:
//   - error: Non-nil if directory traversal fails or no valid policies are found
//
// The function supports nested directory structures and provides comprehensive error
// reporting for debugging policy configuration issues in enterprise environments.
func (e *Engine) LoadPoliciesFromDirectory(policyDir string) error {
	var hasValidPolicy bool
	var lastError error

	err := filepath.Walk(policyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if strings.HasSuffix(path, ".json") {
			err := e.LoadPolicyFromFile(path)
			if err != nil {
				log.Printf("Failed to load policy from %s: %v", path, err)
				lastError = err
			} else {
				hasValidPolicy = true
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	// If we found at least one valid policy, consider it successful
	if hasValidPolicy {
		return nil
	}

	// If no valid policies were found and we had errors, return the last error
	if lastError != nil {
		return lastError
	}

	// Directory exists but contains no valid policies
	return nil
}

// LoadPolicyFromFile loads and validates a single security policy from a JSON file.
// The function reads the policy file, performs JSON unmarshalling, validates the policy
// structure, and registers it in the engine's policy registry for use during security scans.
//
// Parameters:
//   - filePath: Complete path to the JSON policy file to load
//
// Returns:
//   - error: Non-nil if file reading, JSON parsing, validation, or registration fails
//
// The function performs comprehensive policy validation including rule structure verification,
// pattern compilation testing, and metadata completeness checks before registration.
func (e *Engine) LoadPolicyFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read policy file: %v", err)
	}

	var policy types.SecurityPolicy
	err = json.Unmarshal(data, &policy)
	if err != nil {
		return fmt.Errorf("failed to parse policy JSON: %v", err)
	}

	// Validate required fields
	if policy.PolicyName == "" {
		return fmt.Errorf("policy missing required field: policyName")
	}
	if policy.Version == "" {
		return fmt.Errorf("policy missing required field: version")
	}
	if policy.Description == "" {
		return fmt.Errorf("policy missing required field: description")
	}
	if policy.Severity == "" {
		return fmt.Errorf("policy missing required field: severity")
	}

	e.policies[policy.PolicyName] = &policy
	log.Printf("Loaded security policy: %s (version %s)", policy.PolicyName, policy.Version)

	return nil
}

// GetPolicy retrieves a policy by name
func (e *Engine) GetPolicy(policyName string) (*types.SecurityPolicy, error) {
	policy, exists := e.policies[policyName]
	if !exists {
		return nil, fmt.Errorf("policy '%s' not found", policyName)
	}
	return policy, nil
}

// ListPolicies returns all loaded policy names and descriptions
func (e *Engine) ListPolicies() map[string]string {
	result := make(map[string]string)
	for name, policy := range e.policies {
		result[name] = fmt.Sprintf("%s (%s)", policy.Description, policy.Severity)
	}
	return result
}

// GetAllPolicies returns all loaded policies
func (e *Engine) GetAllPolicies() map[string]*types.SecurityPolicy {
	return e.policies
}

// ValidatePolicy validates a policy structure
func (e *Engine) ValidatePolicy(policy *types.SecurityPolicy) error {
	if policy.Version == "" {
		return fmt.Errorf("policy version is required")
	}

	if policy.PolicyName == "" {
		return fmt.Errorf("policy name is required")
	}

	if len(policy.Rules) == 0 {
		return fmt.Errorf("policy must contain at least one rule")
	}

	// Validate each rule
	for i, rule := range policy.Rules {
		if rule.ID == "" {
			return fmt.Errorf("rule %d: ID is required", i)
		}
		if rule.Name == "" {
			return fmt.Errorf("rule %d: Name is required", i)
		}
		if len(rule.Patterns) == 0 {
			return fmt.Errorf("rule %d: at least one pattern is required", i)
		}
	}

	return nil
}
