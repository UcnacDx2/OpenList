package _139

import (
	"strings"
	"testing"
)

// TestValidateThreeFields tests the validation logic for the three required fields
func TestValidateThreeFields(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		password      string
		mailCookies   string
		shouldError   bool
		errorContains string
	}{
		{
			name:        "All three fields present - valid",
			username:    "user@example.com",
			password:    "password123",
			mailCookies: "JSESSIONID=abc123; Os_SSo_Sid=xyz789",
			shouldError: false,
		},
		{
			name:          "Only username present - should error",
			username:      "user@example.com",
			password:      "",
			mailCookies:   "",
			shouldError:   true,
			errorContains: "all three must be provided",
		},
		{
			name:          "Only password present - should error",
			username:      "",
			password:      "password123",
			mailCookies:   "",
			shouldError:   true,
			errorContains: "all three must be provided",
		},
		{
			name:          "Only mailCookies present - should error",
			username:      "",
			password:      "",
			mailCookies:   "JSESSIONID=abc123",
			shouldError:   true,
			errorContains: "all three must be provided",
		},
		{
			name:          "Username and password but no mailCookies - should error",
			username:      "user@example.com",
			password:      "password123",
			mailCookies:   "",
			shouldError:   true,
			errorContains: "all three must be provided",
		},
		{
			name:          "Username and mailCookies but no password - should error",
			username:      "user@example.com",
			password:      "",
			mailCookies:   "JSESSIONID=abc123",
			shouldError:   true,
			errorContains: "all three must be provided",
		},
		{
			name:          "Password and mailCookies but no username - should error",
			username:      "",
			password:      "password123",
			mailCookies:   "JSESSIONID=abc123",
			shouldError:   true,
			errorContains: "all three must be provided",
		},
		{
			name:        "None provided - valid (skip validation)",
			username:    "",
			password:    "",
			mailCookies: "",
			shouldError: false,
		},
		{
			name:        "All three fields with whitespace - valid",
			username:    "  user@example.com  ",
			password:    "  password123  ",
			mailCookies: "  JSESSIONID=abc123  ",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the validation logic directly
			err := validateThreeFields(tt.username, tt.password, tt.mailCookies)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %s", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %s", err.Error())
				}
			}
		})
	}
}

// TestMailCookiesFormat tests that malformed MailCookies are detected
func TestMailCookiesFormat(t *testing.T) {
	tests := []struct {
		name        string
		mailCookies string
		shouldError bool
	}{
		{
			name:        "Valid cookies",
			mailCookies: "JSESSIONID=abc123; Os_SSo_Sid=xyz789",
			shouldError: false,
		},
		{
			name:        "Valid single cookie",
			mailCookies: "JSESSIONID=abc123",
			shouldError: false,
		},
		{
			name:        "Invalid cookies - no equals",
			mailCookies: "JUSTASTRINGWITHOUTEqUALS",
			shouldError: true,
		},
		{
			name:        "Invalid cookies - empty key",
			mailCookies: "=value",
			shouldError: true,
		},
		{
			name:        "Empty string - valid",
			mailCookies: "",
			shouldError: false,
		},
		{
			name:        "Whitespace only - valid (will be trimmed to empty)",
			mailCookies: "   ",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMailCookiesFormat(tt.mailCookies)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error for invalid cookies but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %s", err.Error())
				}
			}
		})
	}
}

