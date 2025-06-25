package logger

import (
	"bytes"
	"strings"
	"testing"
)

func TestLogger_Levels(t *testing.T) {
	tests := []struct {
		name     string
		level    Level
		logFunc  func(*Logger)
		expected []string
		notExpected []string
	}{
		{
			name:  "debug level shows all",
			level: DebugLevel,
			logFunc: func(l *Logger) {
				l.Debug("debug message")
				l.Info("info message")
				l.Warn("warn message")
				l.Error("error message")
			},
			expected: []string{
				"[DEBUG]",
				"[INFO]",
				"[WARN]",
				"[ERROR]",
				"debug message",
				"info message",
				"warn message",
				"error message",
			},
			notExpected: []string{},
		},
		{
			name:  "info level hides debug",
			level: InfoLevel,
			logFunc: func(l *Logger) {
				l.Debug("debug message")
				l.Info("info message")
				l.Warn("warn message")
				l.Error("error message")
			},
			expected: []string{
				"[INFO]",
				"[WARN]",
				"[ERROR]",
				"info message",
				"warn message",
				"error message",
			},
			notExpected: []string{
				"[DEBUG]",
				"debug message",
			},
		},
		{
			name:  "error level only shows errors",
			level: ErrorLevel,
			logFunc: func(l *Logger) {
				l.Debug("debug message")
				l.Info("info message")
				l.Warn("warn message")
				l.Error("error message")
			},
			expected: []string{
				"[ERROR]",
				"error message",
			},
			notExpected: []string{
				"[DEBUG]",
				"[INFO]",
				"[WARN]",
				"debug message",
				"info message",
				"warn message",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := New(buf, "", tt.level)
			
			// Disable colors for testing
			logger.colored = false
			
			tt.logFunc(logger)
			
			output := buf.String()
			
			// Check expected strings
			for _, expected := range tt.expected {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain %q, but it didn't.\nOutput: %s", expected, output)
				}
			}
			
			// Check strings that should not be present
			for _, notExpected := range tt.notExpected {
				if strings.Contains(output, notExpected) {
					t.Errorf("Expected output NOT to contain %q, but it did.\nOutput: %s", notExpected, output)
				}
			}
		})
	}
}

func TestLogger_WithPrefix(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(buf, "", InfoLevel)
	logger.colored = false
	
	// Create logger with prefix
	prefixedLogger := logger.WithPrefix("TEST")
	prefixedLogger.Info("test message")
	
	output := buf.String()
	if !strings.Contains(output, "[TEST]") {
		t.Errorf("Expected output to contain prefix [TEST], but it didn't.\nOutput: %s", output)
	}
	if !strings.Contains(output, "test message") {
		t.Errorf("Expected output to contain message, but it didn't.\nOutput: %s", output)
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
		wantErr  bool
	}{
		{"debug", DebugLevel, false},
		{"DEBUG", DebugLevel, false},
		{"info", InfoLevel, false},
		{"INFO", InfoLevel, false},
		{"warn", WarnLevel, false},
		{"WARN", WarnLevel, false},
		{"warning", WarnLevel, false},
		{"error", ErrorLevel, false},
		{"ERROR", ErrorLevel, false},
		{"fatal", FatalLevel, false},
		{"FATAL", FatalLevel, false},
		{"invalid", InfoLevel, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			level, err := ParseLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && level != tt.expected {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, level, tt.expected)
			}
		})
	}
}

func TestLogger_Format(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := New(buf, "", InfoLevel)
	logger.colored = false
	
	// Test formatting
	logger.Info("Hello %s, you have %d messages", "Alice", 5)
	
	output := buf.String()
	if !strings.Contains(output, "Hello Alice, you have 5 messages") {
		t.Errorf("Expected formatted message, but got: %s", output)
	}
}