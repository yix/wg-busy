package bgp

import (
	"fmt"
	"log"
	"strings"

	biolog "github.com/bio-routing/bio-rd/util/log"
)

// stdLogger adapts Go's standard log package to the bio-rd LoggerInterface.
// This ensures all bio-rd internal messages (FSM state changes, TCP events,
// NOTIFICATION messages, etc.) appear in the wg-busy log output.
type stdLogger struct {
	fields biolog.Fields
}

func newStdLogger() *stdLogger {
	return &stdLogger{}
}

func (l *stdLogger) formatFields() string {
	if len(l.fields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(l.fields))
	for k, v := range l.fields {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return " [" + strings.Join(parts, " ") + "]"
}

func (l *stdLogger) Errorf(format string, args ...interface{}) {
	log.Printf("[BGP ERROR]"+l.formatFields()+" "+format, args...)
}

func (l *stdLogger) Infof(format string, args ...interface{}) {
	log.Printf("[BGP INFO]"+l.formatFields()+" "+format, args...)
}

func (l *stdLogger) Debugf(format string, args ...interface{}) {
	log.Printf("[BGP DEBUG]"+l.formatFields()+" "+format, args...)
}

func (l *stdLogger) Error(msg string) {
	log.Printf("[BGP ERROR]%s %s", l.formatFields(), msg)
}

func (l *stdLogger) Info(msg string) {
	log.Printf("[BGP INFO]%s %s", l.formatFields(), msg)
}

func (l *stdLogger) Debug(msg string) {
	log.Printf("[BGP DEBUG]%s %s", l.formatFields(), msg)
}

func (l *stdLogger) WithFields(fields biolog.Fields) biolog.LoggerInterface {
	merged := make(biolog.Fields, len(l.fields)+len(fields))
	for k, v := range l.fields {
		merged[k] = v
	}
	for k, v := range fields {
		merged[k] = v
	}
	return &stdLogger{fields: merged}
}

func (l *stdLogger) WithError(err error) biolog.LoggerInterface {
	return l.WithFields(biolog.Fields{"error": err})
}
