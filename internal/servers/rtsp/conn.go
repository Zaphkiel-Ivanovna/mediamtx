package rtsp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/bluenviron/gortsplib/v4"
	rtspauth "github.com/bluenviron/gortsplib/v4/pkg/auth"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/headers"
	"github.com/bluenviron/gortsplib/v4/pkg/liberrors"
	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"

	"github.com/bluenviron/mediamtx/internal/auth"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/externalcmd"
	"github.com/bluenviron/mediamtx/internal/hooks"
	"github.com/bluenviron/mediamtx/internal/logger"
	"github.com/bluenviron/mediamtx/internal/protocols/rtsp"
	internalSentry "github.com/bluenviron/mediamtx/internal/sentry"
)

func absoluteURL(req *base.Request, v string) string {
	if strings.HasPrefix(v, "/") {
		ur := base.URL{
			Scheme: req.URL.Scheme,
			Host:   req.URL.Host,
			Path:   v,
		}
		return ur.String()
	}

	return v
}

func credentialsProvided(req *base.Request) bool {
	var auth headers.Authorization
	err := auth.Unmarshal(req.Header["Authorization"])
	return err == nil && auth.Username != ""
}

func contains(list []rtspauth.VerifyMethod, item rtspauth.VerifyMethod) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}
	return false
}

type connParent interface {
	logger.Writer
	findSessionByRSessionUnsafe(rsession *gortsplib.ServerSession) *session
}

type conn struct {
	isTLS               bool
	rtspAddress         string
	authMethods         []rtspauth.VerifyMethod
	readTimeout         conf.Duration
	runOnConnect        string
	runOnConnectRestart bool
	runOnDisconnect     string
	externalCmdPool     *externalcmd.Pool
	pathManager         serverPathManager
	rconn               *gortsplib.ServerConn
	rserver             *gortsplib.Server
	parent              connParent
	sentryManager       *internalSentry.Manager

	uuid             uuid.UUID
	created          time.Time
	onDisconnectHook func()
	sentrySpan       *sentry.Span
	onConnectCmd     *externalcmd.Cmd
	authNonce        string
	authFailures     int
}

func (c *conn) initialize() {
	c.uuid = uuid.New()
	c.created = time.Now()

	c.Log(logger.Info, "opened")

	if c.sentryManager != nil {
		connType := "rtsp"
		if c.isTLS {
			connType = "rtsps"
		}

		remoteAddr := c.rconn.NetConn().RemoteAddr().String()
		sessionID := hex.EncodeToString(c.uuid[:4])

		c.sentrySpan = c.sentryManager.StartConnectionTrace(
			sessionID,
			connType,
			remoteAddr,
		)

		c.sentryManager.SetUser(sessionID, "", c.ip().String())

		c.sentryManager.TraceConnectionEvent(c.sentrySpan, "connection_opened", map[string]interface{}{
			"connection_id": sessionID,
			"remote_addr":   remoteAddr,
			"local_addr":    c.rconn.NetConn().LocalAddr().String(),
			"tls":           c.isTLS,
			"protocol":      "rtsp",
			"created_at":    c.created.Format(time.RFC3339),
		})

		c.sentryManager.AddBreadcrumb("RTSP connection opened", "rtsp_connection", sentry.LevelInfo, map[string]interface{}{
			"connection_id": sessionID,
			"remote_addr":   remoteAddr,
			"tls":           c.isTLS,
		})
	}

	if c.runOnConnect != "" {
		c.Log(logger.Info, "runOnConnect command started")
		_, port, _ := net.SplitHostPort(c.rtspAddress)
		c.onConnectCmd = externalcmd.NewCmd(
			c.externalCmdPool,
			c.runOnConnect,
			c.runOnConnectRestart,
			externalcmd.Environment{
				"RTSP_PATH": "",
				"RTSP_PORT": port,
				"MTX_CONN_TYPE": func() string {
					if c.isTLS {
						return "rtsps"
					}
					return "rtsp"
				}(),
				"MTX_CONN_ID": hex.EncodeToString(c.uuid[:4]),
			},
			func(err error) {
				c.Log(logger.Info, "runOnConnect command exited: %v", err)
			})
	}

	desc := defs.APIPathSourceOrReader{
		Type: func() string {
			if c.isTLS {
				return "rtspsConn"
			}
			return "rtspConn"
		}(),
		ID: c.uuid.String(),
	}

	c.onDisconnectHook = hooks.OnConnect(hooks.OnConnectParams{
		Logger:              c,
		ExternalCmdPool:     c.externalCmdPool,
		RunOnConnect:        c.runOnConnect,
		RunOnConnectRestart: c.runOnConnectRestart,
		RunOnDisconnect:     c.runOnDisconnect,
		RTSPAddress:         c.rtspAddress,
		Desc:                desc,
	})
}

func (c *conn) close() {
	if c.sentryManager != nil && c.sentrySpan != nil {
		sessionID := hex.EncodeToString(c.uuid[:4])
		duration := time.Since(c.created)

		c.sentryManager.TraceConnectionEvent(c.sentrySpan, "connection_closed", map[string]interface{}{
			"connection_id":    sessionID,
			"duration_ms":      duration.Milliseconds(),
			"auth_failures":    c.authFailures,
			"final_auth_nonce": c.authNonce,
		})

		c.sentrySpan.SetData("connection_duration_ms", duration.Milliseconds())
		c.sentrySpan.SetData("auth_failures", c.authFailures)
		c.sentrySpan.Finish()

		c.sentryManager.AddBreadcrumb("RTSP connection closed", "rtsp_connection", sentry.LevelInfo, map[string]interface{}{
			"connection_id": sessionID,
			"duration_ms":   duration.Milliseconds(),
		})
	}

	c.Log(logger.Info, "closed")

	if c.onConnectCmd != nil {
		c.onConnectCmd.Close()
		c.Log(logger.Info, "runOnConnect command stopped")
	}

	c.onDisconnectHook()
}

// Log implements logger.Writer.
func (c *conn) Log(level logger.Level, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	sessionID := hex.EncodeToString(c.uuid[:4])

	c.parent.Log(level, "[conn %s] "+format, append([]interface{}{sessionID}, args...)...)

	if c.sentryManager != nil {
		if level == logger.Error {
			c.sentryManager.CaptureMessage(message, sentry.LevelError, map[string]string{
				"component":     "rtsp_connection",
				"connection_id": sessionID,
				"remote_addr":   c.rconn.NetConn().RemoteAddr().String(),
			})
		}

		c.sentryManager.AddBreadcrumb(message, "rtsp_connection", sentry.LevelInfo, map[string]interface{}{
			"connection_id": sessionID,
			"level":         fmt.Sprintf("%d", level),
		})
	}
}

// Conn returns the RTSP connection.
func (c *conn) Conn() *gortsplib.ServerConn {
	return c.rconn
}

func (c *conn) remoteAddr() net.Addr {
	return c.rconn.NetConn().RemoteAddr()
}

func (c *conn) ip() net.IP {
	return c.rconn.NetConn().RemoteAddr().(*net.TCPAddr).IP
}

func (c *conn) zone() string {
	return c.rconn.NetConn().RemoteAddr().(*net.TCPAddr).Zone
}

// onRequest is called by rtspServer.
func (c *conn) onRequest(req *base.Request) {
	c.Log(logger.Debug, "[c->s] %v", req)

	if c.sentryManager != nil && c.sentrySpan != nil {
		sessionID := hex.EncodeToString(c.uuid[:4])

		c.sentryManager.TraceConnectionEvent(c.sentrySpan, "rtsp_request", map[string]interface{}{
			"connection_id":     sessionID,
			"method":            req.Method,
			"url":               req.URL.String(),
			"path":              req.URL.Path,
			"headers":           req.Header,
			"user_agent":        req.Header["User-Agent"],
			"session_id_header": req.Header["Session"],
		})

		c.sentryManager.AddBreadcrumb(fmt.Sprintf("RTSP %s request", req.Method), "rtsp_request", sentry.LevelInfo, map[string]interface{}{
			"connection_id": sessionID,
			"method":        req.Method,
			"url":           req.URL.String(),
			"user_agent":    req.Header["User-Agent"],
		})
	}
}

// OnResponse implements gortsplib.ServerHandlerOnResponse.
func (c *conn) OnResponse(res *base.Response) {
	c.Log(logger.Debug, "[s->c] %v", res)

	if c.sentryManager != nil && c.sentrySpan != nil {
		sessionID := hex.EncodeToString(c.uuid[:4])

		level := sentry.LevelInfo
		if res.StatusCode >= 400 {
			level = sentry.LevelWarning
		}
		if res.StatusCode >= 500 {
			level = sentry.LevelError
		}

		c.sentryManager.TraceConnectionEvent(c.sentrySpan, "rtsp_response", map[string]interface{}{
			"connection_id": sessionID,
			"status_code":   res.StatusCode,
			"headers":       res.Header,
		})

		c.sentryManager.AddBreadcrumb(fmt.Sprintf("RTSP response %d", res.StatusCode), "rtsp_response", level, map[string]interface{}{
			"connection_id": sessionID,
			"status_code":   res.StatusCode,
		})
	}
}

// onDescribe is called by rtspServer.
func (c *conn) onDescribe(ctx *gortsplib.ServerHandlerOnDescribeCtx,
) (*base.Response, *gortsplib.ServerStream, error) {
	if len(ctx.Path) == 0 || ctx.Path[0] != '/' {
		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, nil, fmt.Errorf("invalid path")
	}
	ctx.Path = ctx.Path[1:]

	// CustomVerifyFunc prevents hashed credentials from working.
	// Use it only when strictly needed.
	var customVerifyFunc func(expectedUser, expectedPass string) bool
	if contains(c.authMethods, rtspauth.VerifyMethodDigestMD5) {
		customVerifyFunc = func(expectedUser, expectedPass string) bool {
			return c.rconn.VerifyCredentials(ctx.Request, expectedUser, expectedPass)
		}
	}

	req := defs.PathAccessRequest{
		Name:             ctx.Path,
		Query:            ctx.Query,
		Proto:            auth.ProtocolRTSP,
		ID:               &c.uuid,
		Credentials:      rtsp.Credentials(ctx.Request),
		IP:               c.ip(),
		CustomVerifyFunc: customVerifyFunc,
	}

	res := c.pathManager.Describe(defs.PathDescribeReq{
		AccessRequest: req,
	})

	if res.Err != nil {
		var terr auth.Error
		if errors.As(res.Err, &terr) {
			res, err2 := c.handleAuthError(ctx.Request)
			return res, nil, err2
		}

		var terr2 defs.PathNoStreamAvailableError
		if errors.As(res.Err, &terr2) {
			return &base.Response{
				StatusCode: base.StatusNotFound,
			}, nil, res.Err
		}

		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, nil, res.Err
	}

	if res.Redirect != "" {
		return &base.Response{
			StatusCode: base.StatusMovedPermanently,
			Header: base.Header{
				"Location": base.HeaderValue{absoluteURL(ctx.Request, res.Redirect)},
			},
		}, nil, nil
	}

	var stream *gortsplib.ServerStream
	if !c.isTLS {
		stream = res.Stream.RTSPStream(c.rserver)
	} else {
		stream = res.Stream.RTSPSStream(c.rserver)
	}

	return &base.Response{
		StatusCode: base.StatusOK,
	}, stream, nil
}

func (c *conn) handleAuthError(req *base.Request) (*base.Response, error) {
	if credentialsProvided(req) {
		// wait some seconds to mitigate brute force attacks
		<-time.After(auth.PauseAfterError)
	}

	// let gortsplib decide whether connection should be terminated,
	// depending on whether credentials have been provided or not.
	return &base.Response{
		StatusCode: base.StatusUnauthorized,
	}, liberrors.ErrServerAuth{}
}

func (c *conn) apiItem() *defs.APIRTSPConn {
	stats := c.rconn.Stats()

	return &defs.APIRTSPConn{
		ID:            c.uuid,
		Created:       c.created,
		RemoteAddr:    c.remoteAddr().String(),
		BytesReceived: stats.BytesReceived,
		BytesSent:     stats.BytesSent,
		Session: func() *uuid.UUID {
			sx := c.parent.findSessionByRSessionUnsafe(c.rconn.Session())
			if sx != nil {
				return &sx.uuid
			}
			return nil
		}(),
	}
}

// onClose is called by rtspServer.
func (c *conn) onClose(err error) {
	if c.sentryManager != nil && c.sentrySpan != nil {
		sessionID := hex.EncodeToString(c.uuid[:4])

		c.sentryManager.TraceConnectionEvent(c.sentrySpan, "connection_error_close", map[string]interface{}{
			"connection_id": sessionID,
			"error":         err.Error(),
		})

		if err != nil {
			c.sentryManager.CaptureError(err, map[string]string{
				"component":     "rtsp_connection",
				"connection_id": sessionID,
				"remote_addr":   c.rconn.NetConn().RemoteAddr().String(),
				"event":         "close_error",
			})
		}
	}

	c.Log(logger.Info, "closed: %v", err)
	c.close()
}
