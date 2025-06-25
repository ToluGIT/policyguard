package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// Level represents the logging level
type Level int

const (
	// DebugLevel logs everything
	DebugLevel Level = iota
	// InfoLevel logs info, warnings, and errors
	InfoLevel
	// WarnLevel logs warnings and errors
	WarnLevel
	// ErrorLevel logs only errors
	ErrorLevel
	// FatalLevel logs fatal errors and exits
	FatalLevel
)

var (
	// Default logger instance
	defaultLogger *Logger
	once          sync.Once
)

// Logger represents a logger instance
type Logger struct {
	mu       sync.RWMutex
	level    Level
	output   io.Writer
	prefix   string
	colored  bool
	logger   *log.Logger
}

// Color codes for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[37m"
)

// New creates a new logger instance
func New(output io.Writer, prefix string, level Level) *Logger {
	return &Logger{
		level:   level,
		output:  output,
		prefix:  prefix,
		colored: isTerminal(output),
		logger:  log.New(output, "", log.LstdFlags),
	}
}

// Default returns the default logger instance
func Default() *Logger {
	once.Do(func() {
		defaultLogger = New(os.Stderr, "", InfoLevel)
	})
	return defaultLogger
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetOutput sets the output writer
func (l *Logger) SetOutput(output io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = output
	l.colored = isTerminal(output)
	l.logger.SetOutput(output)
}

// SetPrefix sets the logger prefix
func (l *Logger) SetPrefix(prefix string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prefix = prefix
}

// WithPrefix creates a new logger with the given prefix
func (l *Logger) WithPrefix(prefix string) *Logger {
	return &Logger{
		level:   l.level,
		output:  l.output,
		prefix:  prefix,
		colored: l.colored,
		logger:  log.New(l.output, "", log.LstdFlags),
	}
}

// log logs a message at the given level
func (l *Logger) log(level Level, format string, args ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if level < l.level {
		return
	}

	msg := fmt.Sprintf(format, args...)
	if l.prefix != "" {
		msg = fmt.Sprintf("[%s] %s", l.prefix, msg)
	}

	// Add caller information for debug level
	if l.level == DebugLevel {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			file = filepath.Base(file)
			msg = fmt.Sprintf("%s:%d %s", file, line, msg)
		}
	}

	// Add color if supported
	if l.colored {
		switch level {
		case DebugLevel:
			msg = colorGray + "[DEBUG] " + colorReset + msg
		case InfoLevel:
			msg = colorBlue + "[INFO] " + colorReset + msg
		case WarnLevel:
			msg = colorYellow + "[WARN] " + colorReset + msg
		case ErrorLevel:
			msg = colorRed + "[ERROR] " + colorReset + msg
		case FatalLevel:
			msg = colorRed + "[FATAL] " + colorReset + msg
		}
	} else {
		levelStr := levelToString(level)
		msg = fmt.Sprintf("[%s] %s", levelStr, msg)
	}

	l.logger.Println(msg)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DebugLevel, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(InfoLevel, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WarnLevel, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ErrorLevel, format, args...)
}

// Fatal logs a fatal error message and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(FatalLevel, format, args...)
	os.Exit(1)
}

// Package-level convenience functions using the default logger

// Debug logs a debug message using the default logger
func Debug(format string, args ...interface{}) {
	Default().Debug(format, args...)
}

// Info logs an info message using the default logger
func Info(format string, args ...interface{}) {
	Default().Info(format, args...)
}

// Warn logs a warning message using the default logger
func Warn(format string, args ...interface{}) {
	Default().Warn(format, args...)
}

// Error logs an error message using the default logger
func Error(format string, args ...interface{}) {
	Default().Error(format, args...)
}

// Fatal logs a fatal error message using the default logger and exits
func Fatal(format string, args ...interface{}) {
	Default().Fatal(format, args...)
}

// SetLevel sets the logging level for the default logger
func SetLevel(level Level) {
	Default().SetLevel(level)
}

// SetOutput sets the output for the default logger
func SetOutput(output io.Writer) {
	Default().SetOutput(output)
}

// Helper functions

// isTerminal checks if the writer is a terminal
func isTerminal(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		return isatty(f.Fd())
	}
	return false
}

// levelToString converts a log level to string
func levelToString(level Level) string {
	switch level {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	case FatalLevel:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel parses a string into a log level
func ParseLevel(s string) (Level, error) {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return DebugLevel, nil
	case "INFO":
		return InfoLevel, nil
	case "WARN", "WARNING":
		return WarnLevel, nil
	case "ERROR":
		return ErrorLevel, nil
	case "FATAL":
		return FatalLevel, nil
	default:
		return InfoLevel, fmt.Errorf("unknown log level: %s", s)
	}
}