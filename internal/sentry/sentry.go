package sentry

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/getsentry/sentry-go"

	"github.com/bluenviron/mediamtx/internal/logger"
)

type ErrorFilter struct {
	ErrorTypes []string

	ErrorMessages []string

	ErrorPrefixes []string
}

type Manager struct {
	initialized bool
	filter      ErrorFilter
}

func NewManager() *Manager {
	return &Manager{
		filter: ErrorFilter{
			ErrorTypes: []string{
				"liberrors.ErrServerSessionTornDown",
				"liberrors.ErrServerTerminated",
				"liberrors.ErrServerClosed",
				"liberrors.ErrServerSessionNotFound",
			},
			ErrorMessages: []string{
				"connection closed",
				"context canceled",
				"EOF",
				"broken pipe",
				"connection reset by peer",
			},
			ErrorPrefixes: []string{
				"read tcp",
				"write tcp",
				"dial tcp",
				"torn down by",
				"server terminated",
				"EOF",
			},
		},
	}
}

func (m *Manager) AddErrorFilter(errorType, errorMessage, errorPrefix string) {
	if errorType != "" {
		m.filter.ErrorTypes = append(m.filter.ErrorTypes, errorType)
	}
	if errorMessage != "" {
		m.filter.ErrorMessages = append(m.filter.ErrorMessages, errorMessage)
	}
	if errorPrefix != "" {
		m.filter.ErrorPrefixes = append(m.filter.ErrorPrefixes, errorPrefix)
	}
}

func (m *Manager) shouldIgnoreError(err error) bool {
	if err == nil {
		return true
	}

	errMsg := err.Error()
	errType := fmt.Sprintf("%T", err)

	for _, pattern := range m.filter.ErrorTypes {
		if strings.Contains(errType, pattern) {
			return true
		}
	}

	for _, pattern := range m.filter.ErrorMessages {
		if strings.Contains(errMsg, pattern) {
			return true
		}
	}

	for _, prefix := range m.filter.ErrorPrefixes {
		if strings.HasPrefix(errMsg, prefix) {
			return true
		}
	}

	return false
}

func (m *Manager) Initialize(dsn string) error {
	if dsn == "" {
		return nil
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Environment:      getEnvOrDefault("MEDIAMTX_ENV", "production"),
		Release:          getVersion(),
		Debug:            getEnvOrDefault("SENTRY_DEBUG", "false") == "true",
		AttachStacktrace: true,
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {

			if hint.OriginalException != nil {
				if m.shouldIgnoreError(hint.OriginalException) {
					return nil
				}
			}

			event.ServerName = ""
			return event
		},
		TracesSampleRate: 1.0,
		EnableTracing:    true,
	})

	if err != nil {
		return err
	}

	m.initialized = true
	return nil
}

func (m *Manager) IsInitialized() bool {
	return m.initialized
}

func (m *Manager) Close() {
	if m.initialized {
		sentry.Flush(2 * 1000 * 1000 * 1000) // 2 seconds
		m.initialized = false
	}
}

func (m *Manager) CaptureError(err error, tags map[string]string) {
	if !m.initialized || m.shouldIgnoreError(err) {
		return
	}

	sentry.WithScope(func(scope *sentry.Scope) {
		for key, value := range tags {
			scope.SetTag(key, value)
		}
		sentry.CaptureException(err)
	})
}

func (m *Manager) CaptureMessage(message string, level sentry.Level, tags map[string]string) {
	if !m.initialized {
		return
	}

	for _, pattern := range m.filter.ErrorMessages {
		if strings.Contains(message, pattern) {
			return
		}
	}

	sentry.WithScope(func(scope *sentry.Scope) {
		for key, value := range tags {
			scope.SetTag(key, value)
		}
		sentry.CaptureMessage(message)
	})
}

func (m *Manager) StartTransaction(ctx context.Context, name string, operation string) *sentry.Span {
	return sentry.StartTransaction(ctx, name, sentry.WithTransactionName(name)).StartChild(operation)
}

func (m *Manager) StartConnectionTrace(sessionID, connType, remoteAddr string) *sentry.Span {
	if !m.initialized {
		return nil
	}

	transaction := sentry.StartTransaction(context.Background(), fmt.Sprintf("%s Connection", strings.ToUpper(connType)))
	transaction.SetTag("component", strings.ToLower(connType))
	transaction.SetTag("session_id", sessionID)
	transaction.SetTag("remote_addr", remoteAddr)
	transaction.SetTag("connection_type", connType)

	return transaction
}

// StartHTTPTransaction starts a new HTTP transaction for request tracing
func (m *Manager) StartHTTPTransaction(ctx context.Context, method, path, userAgent, remoteAddr string) *sentry.Span {
	if !m.initialized {
		return nil
	}

	name := fmt.Sprintf("%s %s", method, path)
	transaction := sentry.StartTransaction(ctx, name)
	transaction.SetTag("component", "http")
	transaction.SetTag("http.method", method)
	transaction.SetTag("http.path", path)
	transaction.SetTag("http.user_agent", userAgent)
	transaction.SetTag("remote_addr", remoteAddr)
	transaction.SetTag("request_type", "HTTP")

	return transaction
}

// StartRTMPTransaction starts a new RTMP transaction for connection tracing
func (m *Manager) StartRTMPTransaction(ctx context.Context, sessionID, remoteAddr, path string, publish bool) *sentry.Span {
	if !m.initialized {
		return nil
	}

	operation := "read"
	if publish {
		operation = "publish"
	}

	name := fmt.Sprintf("RTMP %s %s", operation, path)
	transaction := sentry.StartTransaction(ctx, name)
	transaction.SetTag("component", "rtmp")
	transaction.SetTag("session_id", sessionID)
	transaction.SetTag("remote_addr", remoteAddr)
	transaction.SetTag("path", path)
	transaction.SetTag("operation", operation)
	transaction.SetTag("connection_type", "RTMP")

	return transaction
}

// StartRTSPTransaction starts a new RTSP transaction for session tracing
func (m *Manager) StartRTSPTransaction(ctx context.Context, sessionID, remoteAddr, path string) *sentry.Span {
	if !m.initialized {
		return nil
	}

	name := fmt.Sprintf("RTSP Session %s", path)
	transaction := sentry.StartTransaction(ctx, name)
	transaction.SetTag("component", "rtsp")
	transaction.SetTag("session_id", sessionID)
	transaction.SetTag("remote_addr", remoteAddr)
	transaction.SetTag("path", path)
	transaction.SetTag("connection_type", "RTSP")

	return transaction
}

func (m *Manager) TraceConnectionEvent(parent *sentry.Span, operation string, data map[string]interface{}) {
	if !m.initialized || parent == nil {
		return
	}

	child := parent.StartChild(operation)
	defer child.Finish()

	for key, value := range data {
		child.SetData(key, value)
	}
}

// TraceHTTPRequest traces an HTTP request with detailed information
func (m *Manager) TraceHTTPRequest(parent *sentry.Span, method, path, userAgent string, statusCode int, responseTime int64, data map[string]interface{}) {
	if !m.initialized || parent == nil {
		return
	}

	child := parent.StartChild("http.request")
	defer child.Finish()

	child.SetData("http.method", method)
	child.SetData("http.path", path)
	child.SetData("http.user_agent", userAgent)
	child.SetData("http.status_code", statusCode)
	child.SetData("http.response_time_ms", responseTime)

	// Set status based on HTTP status code
	if statusCode >= 200 && statusCode < 300 {
		child.SetTag("http.status_class", "success")
	} else if statusCode >= 400 && statusCode < 500 {
		child.SetTag("http.status_class", "client_error")
	} else if statusCode >= 500 {
		child.SetTag("http.status_class", "server_error")
	}

	for key, value := range data {
		child.SetData(key, value)
	}
}

func (m *Manager) SetUser(sessionID, username, ipAddress string) {
	if !m.initialized {
		return
	}

	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetUser(sentry.User{
			ID:        sessionID,
			Username:  username,
			IPAddress: ipAddress,
		})
	})
}

func (m *Manager) AddBreadcrumb(message, category string, level sentry.Level, data map[string]interface{}) {
	if !m.initialized {
		return
	}

	sentry.AddBreadcrumb(&sentry.Breadcrumb{
		Message:  message,
		Category: category,
		Level:    level,
		Data:     data,
	})
}

func (m *Manager) WithConnectionContext(sessionID string, connType string) context.Context {
	return sentry.SetHubOnContext(context.Background(), sentry.NewHub(sentry.CurrentHub().Client(), sentry.NewScope()))
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getVersion() string {
	if version, err := os.ReadFile("VERSION"); err == nil {
		return strings.TrimSpace(string(version))
	}
	return "dev"
}

func LogLevelToSentryLevel(level logger.Level) sentry.Level {
	switch level {
	case logger.Error:
		return sentry.LevelError
	case logger.Warn:
		return sentry.LevelWarning
	case logger.Info:
		return sentry.LevelInfo
	case logger.Debug:
		return sentry.LevelDebug
	default:
		return sentry.LevelInfo
	}
}
