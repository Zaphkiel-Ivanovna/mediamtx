package rtsp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/bluenviron/gortsplib/v4"
	rtspauth "github.com/bluenviron/gortsplib/v4/pkg/auth"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"

	"github.com/bluenviron/mediamtx/internal/auth"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/counterdumper"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/externalcmd"
	"github.com/bluenviron/mediamtx/internal/hooks"
	"github.com/bluenviron/mediamtx/internal/logger"
	"github.com/bluenviron/mediamtx/internal/protocols/rtsp"
	internalSentry "github.com/bluenviron/mediamtx/internal/sentry"
	"github.com/bluenviron/mediamtx/internal/stream"
)

type session struct {
	isTLS           bool
	transports      conf.RTSPTransports
	rsession        *gortsplib.ServerSession
	rconn           *gortsplib.ServerConn
	rserver         *gortsplib.Server
	externalCmdPool *externalcmd.Pool
	pathManager     serverPathManager
	parent          logger.Writer
	sentryManager   *internalSentry.Manager

	uuid            uuid.UUID
	created         time.Time
	path            defs.Path
	stream          *stream.Stream
	onUnreadHook    func()
	mutex           sync.Mutex
	state           gortsplib.ServerSessionState
	transport       *gortsplib.Transport
	pathName        string
	query           string
	packetsLost     *counterdumper.CounterDumper
	decodeErrors    *counterdumper.CounterDumper
	discardedFrames *counterdumper.CounterDumper
	sentrySpan      *sentry.Span
	sessionID       string
}

func (s *session) initialize() {
	s.uuid = uuid.New()
	s.created = time.Now()
	s.sessionID = hex.EncodeToString(s.uuid[:4])

	if s.sentryManager != nil {
		connType := "rtsp"
		if s.isTLS {
			connType = "rtsps"
		}

		remoteAddr := s.rconn.NetConn().RemoteAddr().String()

		s.sentrySpan = s.sentryManager.StartConnectionTrace(
			s.sessionID,
			connType,
			remoteAddr,
		)

		s.sentryManager.SetUser(s.sessionID, "", s.rconn.NetConn().RemoteAddr().(*net.TCPAddr).IP.String())

		s.sentryManager.TraceConnectionEvent(s.sentrySpan, "session_created", map[string]interface{}{
			"session_id":  s.sessionID,
			"remote_addr": remoteAddr,
			"tls":         s.isTLS,
			"transports":  fmt.Sprintf("%v", s.transports),
			"created_at":  s.created.Format(time.RFC3339),
		})

		s.sentryManager.AddBreadcrumb("RTSP session created", "rtsp_session", sentry.LevelInfo, map[string]interface{}{
			"session_id":  s.sessionID,
			"remote_addr": remoteAddr,
			"tls":         s.isTLS,
		})
	}

	s.packetsLost = &counterdumper.CounterDumper{
		OnReport: func(val uint64) {
			s.Log(logger.Warn, "%d RTP %s lost",
				val,
				func() string {
					if val == 1 {
						return "packet"
					}
					return "packets"
				}())

			if s.sentryManager != nil {
				s.sentryManager.TraceConnectionEvent(s.sentrySpan, "packets_lost", map[string]interface{}{
					"session_id":    s.sessionID,
					"packets_count": val,
					"path":          s.pathName,
				})

				s.sentryManager.AddBreadcrumb("RTP packets lost", "rtsp_session", sentry.LevelWarning, map[string]interface{}{
					"session_id":    s.sessionID,
					"packets_count": val,
				})
			}
		},
	}
	s.packetsLost.Start()

	s.decodeErrors = &counterdumper.CounterDumper{
		OnReport: func(val uint64) {
			s.Log(logger.Warn, "%d decode %s",
				val,
				func() string {
					if val == 1 {
						return "error"
					}
					return "errors"
				}())

			if s.sentryManager != nil {
				s.sentryManager.TraceConnectionEvent(s.sentrySpan, "decode_errors", map[string]interface{}{
					"session_id":   s.sessionID,
					"errors_count": val,
					"path":         s.pathName,
				})

				s.sentryManager.CaptureMessage(fmt.Sprintf("Decode errors in session %s: %d", s.sessionID, val),
					sentry.LevelWarning, map[string]string{
						"component":   "rtsp_session",
						"session_id":  s.sessionID,
						"path":        s.pathName,
						"remote_addr": s.rconn.NetConn().RemoteAddr().String(),
					})
			}
		},
	}
	s.decodeErrors.Start()

	s.discardedFrames = &counterdumper.CounterDumper{
		OnReport: func(val uint64) {
			s.Log(logger.Warn, "connection is too slow, discarding %d %s",
				val,
				func() string {
					if val == 1 {
						return "frame"
					}
					return "frames"
				}())

			if s.sentryManager != nil {
				s.sentryManager.TraceConnectionEvent(s.sentrySpan, "frames_discarded", map[string]interface{}{
					"session_id":   s.sessionID,
					"frames_count": val,
					"path":         s.pathName,
					"reason":       "connection_too_slow",
				})

				s.sentryManager.CaptureMessage(fmt.Sprintf("Slow connection - discarded %d frames in session %s", val, s.sessionID),
					sentry.LevelWarning, map[string]string{
						"component":   "rtsp_session",
						"session_id":  s.sessionID,
						"path":        s.pathName,
						"remote_addr": s.rconn.NetConn().RemoteAddr().String(),
					})
			}
		},
	}
	s.discardedFrames.Start()

	s.Log(logger.Info, "created by %v", s.rconn.NetConn().RemoteAddr())
}

// Close closes a Session.
func (s *session) Close() {
	s.discardedFrames.Stop()
	s.decodeErrors.Stop()
	s.packetsLost.Stop()
	s.rsession.Close()
}

func (s *session) remoteAddr() net.Addr {
	return s.rconn.NetConn().RemoteAddr()
}

// Log implements logger.Writer.
func (s *session) Log(level logger.Level, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	s.parent.Log(level, "[session %s] "+format, append([]interface{}{s.sessionID}, args...)...)

	if s.sentryManager != nil {
		if level == logger.Error {
			s.sentryManager.CaptureMessage(message, sentry.LevelError, map[string]string{
				"component":   "rtsp_session",
				"session_id":  s.sessionID,
				"path":        s.pathName,
				"remote_addr": s.rconn.NetConn().RemoteAddr().String(),
			})
		}

		s.sentryManager.AddBreadcrumb(message, "rtsp_session", sentry.LevelInfo, map[string]interface{}{
			"session_id": s.sessionID,
			"level":      fmt.Sprintf("%d", level),
			"path":       s.pathName,
		})
	}
}

// onClose is called by rtspServer.
func (s *session) onClose(err error) {
	if s.rsession.State() == gortsplib.ServerSessionStatePlay {
		s.onUnreadHook()
	}

	switch s.rsession.State() {
	case gortsplib.ServerSessionStatePrePlay, gortsplib.ServerSessionStatePlay:
		s.path.RemoveReader(defs.PathRemoveReaderReq{Author: s})

	case gortsplib.ServerSessionStatePreRecord, gortsplib.ServerSessionStateRecord:
		s.path.RemovePublisher(defs.PathRemovePublisherReq{Author: s})
	}

	s.path = nil
	s.stream = nil

	if s.sentryManager != nil && s.sentrySpan != nil {
		duration := time.Since(s.created)

		s.sentryManager.TraceConnectionEvent(s.sentrySpan, "session_closed", map[string]interface{}{
			"session_id":  s.sessionID,
			"duration_ms": duration.Milliseconds(),
			"final_state": s.rsession.State().String(),
			"path":        s.pathName,
			"error":       err.Error(),
		})

		s.sentrySpan.SetData("session_duration_ms", duration.Milliseconds())
		s.sentrySpan.SetData("final_state", s.rsession.State().String())
		s.sentrySpan.SetData("path", s.pathName)

		if err != nil {
			s.sentryManager.CaptureError(err, map[string]string{
				"component":   "rtsp_session",
				"session_id":  s.sessionID,
				"path":        s.pathName,
				"remote_addr": s.rconn.NetConn().RemoteAddr().String(),
				"event":       "session_close",
			})
		}

		s.sentrySpan.Finish()
	}

	s.Log(logger.Info, "destroyed: %v", err)
}

// onAnnounce is called by rtspServer.
func (s *session) onAnnounce(c *conn, ctx *gortsplib.ServerHandlerOnAnnounceCtx) (*base.Response, error) {
	if len(ctx.Path) == 0 || ctx.Path[0] != '/' {
		if s.sentryManager != nil {
			s.sentryManager.TraceConnectionEvent(s.sentrySpan, "announce_error", map[string]interface{}{
				"session_id": s.sessionID,
				"error":      "invalid_path",
				"path":       ctx.Path,
			})
		}
		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, fmt.Errorf("invalid path")
	}
	ctx.Path = ctx.Path[1:]

	if s.sentryManager != nil {
		s.sentryManager.TraceConnectionEvent(s.sentrySpan, "announce_started", map[string]interface{}{
			"session_id":   s.sessionID,
			"path":         ctx.Path,
			"query":        ctx.Query,
			"remote_addr":  s.rconn.NetConn().RemoteAddr().String(),
			"content_type": ctx.Request.Header["Content-Type"],
			"user_agent":   ctx.Request.Header["User-Agent"],
		})

		s.sentryManager.AddBreadcrumb("RTSP ANNOUNCE started", "rtsp_action", sentry.LevelInfo, map[string]interface{}{
			"session_id": s.sessionID,
			"path":       ctx.Path,
			"action":     "ANNOUNCE",
		})
	}

	// CustomVerifyFunc prevents hashed credentials from working.
	// Use it only when strictly needed.
	var customVerifyFunc func(expectedUser, expectedPass string) bool
	if contains(c.authMethods, rtspauth.VerifyMethodDigestMD5) {
		customVerifyFunc = func(expectedUser, expectedPass string) bool {
			return c.rconn.VerifyCredentials(ctx.Request, expectedUser, expectedPass)
		}
	}

	credentials := rtsp.Credentials(ctx.Request)

	req := defs.PathAccessRequest{
		Name:             ctx.Path,
		Query:            ctx.Query,
		Publish:          true,
		Proto:            auth.ProtocolRTSP,
		ID:               &c.uuid,
		Credentials:      credentials,
		IP:               c.ip(),
		CustomVerifyFunc: customVerifyFunc,
	}

	path, err := s.pathManager.AddPublisher(defs.PathAddPublisherReq{
		Author:        s,
		AccessRequest: req,
	})
	if err != nil {
		if s.sentryManager != nil {
			s.sentryManager.TraceConnectionEvent(s.sentrySpan, "announce_failed", map[string]interface{}{
				"session_id": s.sessionID,
				"path":       ctx.Path,
				"error":      err.Error(),
				"username":   credentials.User,
			})

			s.sentryManager.CaptureError(err, map[string]string{
				"component":  "rtsp_session",
				"session_id": s.sessionID,
				"path":       ctx.Path,
				"action":     "ANNOUNCE",
				"username":   credentials.User,
			})
		}

		var terr auth.Error
		if errors.As(err, &terr) {
			return c.handleAuthError(ctx.Request)
		}

		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, err
	}

	s.path = path

	s.mutex.Lock()
	s.state = gortsplib.ServerSessionStatePreRecord
	s.pathName = ctx.Path
	s.query = ctx.Query
	s.mutex.Unlock()

	if s.sentryManager != nil {
		s.sentryManager.TraceConnectionEvent(s.sentrySpan, "announce_success", map[string]interface{}{
			"session_id": s.sessionID,
			"path":       ctx.Path,
			"state":      "PreRecord",
			"username":   credentials.User,
		})

		s.sentryManager.SetUser(s.sessionID, credentials.User, s.rconn.NetConn().RemoteAddr().(*net.TCPAddr).IP.String())

		s.sentryManager.AddBreadcrumb("RTSP ANNOUNCE successful", "rtsp_action", sentry.LevelInfo, map[string]interface{}{
			"session_id": s.sessionID,
			"path":       ctx.Path,
			"username":   credentials.User,
		})
	}

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// onSetup is called by rtspServer.
func (s *session) onSetup(c *conn, ctx *gortsplib.ServerHandlerOnSetupCtx,
) (*base.Response, *gortsplib.ServerStream, error) {
	if len(ctx.Path) == 0 || ctx.Path[0] != '/' {
		if s.sentryManager != nil {
			s.sentryManager.TraceConnectionEvent(s.sentrySpan, "setup_error", map[string]interface{}{
				"session_id": s.sessionID,
				"error":      "invalid_path",
				"path":       ctx.Path,
			})
		}
		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, nil, fmt.Errorf("invalid path")
	}
	ctx.Path = ctx.Path[1:]

	if s.sentryManager != nil {
		s.sentryManager.TraceConnectionEvent(s.sentrySpan, "setup_started", map[string]interface{}{
			"session_id": s.sessionID,
			"path":       ctx.Path,
			"query":      ctx.Query,
			"transport":  ctx.Transport.String(),
			"state":      s.rsession.State().String(),
		})

		s.sentryManager.AddBreadcrumb("RTSP SETUP started", "rtsp_action", sentry.LevelInfo, map[string]interface{}{
			"session_id": s.sessionID,
			"path":       ctx.Path,
			"transport":  ctx.Transport.String(),
			"action":     "SETUP",
		})
	}

	// in case the client is setupping a stream with UDP or UDP-multicast, and these
	// transport protocols are disabled, gortsplib already blocks the request.
	// we have only to handle the case in which the transport protocol is TCP
	// and it is disabled.
	if ctx.Transport == gortsplib.TransportTCP {
		if _, ok := s.transports[gortsplib.TransportTCP]; !ok {
			if s.sentryManager != nil {
				s.sentryManager.TraceConnectionEvent(s.sentrySpan, "setup_failed", map[string]interface{}{
					"session_id": s.sessionID,
					"path":       ctx.Path,
					"error":      "unsupported_transport_tcp",
					"transport":  "TCP",
				})
			}
			return &base.Response{
				StatusCode: base.StatusUnsupportedTransport,
			}, nil, nil
		}
	}

	switch s.rsession.State() {
	case gortsplib.ServerSessionStateInitial, gortsplib.ServerSessionStatePrePlay: // play
		credentials := rtsp.Credentials(ctx.Request)

		req := defs.PathAccessRequest{
			Name:        ctx.Path,
			Query:       ctx.Query,
			Proto:       auth.ProtocolRTSP,
			ID:          &c.uuid,
			Credentials: credentials,
			IP:          c.ip(),
			CustomVerifyFunc: func(expectedUser, expectedPass string) bool {
				return c.rconn.VerifyCredentials(ctx.Request, expectedUser, expectedPass)
			},
		}

		path, stream, err := s.pathManager.AddReader(defs.PathAddReaderReq{
			Author:        s,
			AccessRequest: req,
		})
		if err != nil {
			if s.sentryManager != nil {
				s.sentryManager.TraceConnectionEvent(s.sentrySpan, "setup_reader_failed", map[string]interface{}{
					"session_id": s.sessionID,
					"path":       ctx.Path,
					"error":      err.Error(),
					"username":   credentials.User,
				})

				s.sentryManager.CaptureError(err, map[string]string{
					"component":  "rtsp_session",
					"session_id": s.sessionID,
					"path":       ctx.Path,
					"action":     "SETUP_READ",
					"username":   credentials.User,
				})
			}

			var terr auth.Error
			if errors.As(err, &terr) {
				res, err2 := c.handleAuthError(ctx.Request)
				return res, nil, err2
			}

			var terr2 defs.PathNoStreamAvailableError
			if errors.As(err, &terr2) {
				return &base.Response{
					StatusCode: base.StatusNotFound,
				}, nil, err
			}

			return &base.Response{
				StatusCode: base.StatusBadRequest,
			}, nil, err
		}

		s.path = path
		s.stream = stream

		s.mutex.Lock()
		s.state = gortsplib.ServerSessionStatePrePlay
		s.pathName = ctx.Path
		s.query = ctx.Query
		s.mutex.Unlock()

		if s.sentryManager != nil {
			s.sentryManager.TraceConnectionEvent(s.sentrySpan, "setup_reader_success", map[string]interface{}{
				"session_id": s.sessionID,
				"path":       ctx.Path,
				"state":      "PrePlay",
				"username":   credentials.User,
			})

			s.sentryManager.SetUser(s.sessionID, credentials.User, s.rconn.NetConn().RemoteAddr().(*net.TCPAddr).IP.String())
		}

		var rstream *gortsplib.ServerStream
		if !s.isTLS {
			rstream = stream.RTSPStream(s.rserver)
		} else {
			rstream = stream.RTSPSStream(s.rserver)
		}

		return &base.Response{
			StatusCode: base.StatusOK,
		}, rstream, nil

	default: // record
		if s.sentryManager != nil {
			s.sentryManager.TraceConnectionEvent(s.sentrySpan, "setup_publisher_success", map[string]interface{}{
				"session_id": s.sessionID,
				"path":       ctx.Path,
				"state":      s.rsession.State().String(),
			})
		}

		return &base.Response{
			StatusCode: base.StatusOK,
		}, nil, nil
	}
}

// onPlay is called by rtspServer.
func (s *session) onPlay(_ *gortsplib.ServerHandlerOnPlayCtx) (*base.Response, error) {
	h := make(base.Header)

	if s.rsession.State() == gortsplib.ServerSessionStatePrePlay {
		s.Log(logger.Info, "is reading from path '%s', with %s, %s",
			s.path.Name(),
			s.rsession.SetuppedTransport(),
			defs.MediasInfo(s.rsession.SetuppedMedias()))

		if s.sentryManager != nil {
			medias := s.rsession.SetuppedMedias()
			s.sentryManager.TraceConnectionEvent(s.sentrySpan, "play_started", map[string]interface{}{
				"session_id":  s.sessionID,
				"path":        s.path.Name(),
				"transport":   s.rsession.SetuppedTransport().String(),
				"media_count": len(medias),
				"medias_info": defs.MediasInfo(medias),
				"query":       s.rsession.SetuppedQuery(),
				"state":       "Play",
			})

			s.sentryManager.AddBreadcrumb("RTSP PLAY started", "rtsp_action", sentry.LevelInfo, map[string]interface{}{
				"session_id":  s.sessionID,
				"path":        s.path.Name(),
				"transport":   s.rsession.SetuppedTransport().String(),
				"media_count": len(medias),
				"action":      "PLAY",
			})
		}

		s.onUnreadHook = hooks.OnRead(hooks.OnReadParams{
			Logger:          s,
			ExternalCmdPool: s.externalCmdPool,
			Conf:            s.path.SafeConf(),
			ExternalCmdEnv:  s.path.ExternalCmdEnv(),
			Reader:          s.APIReaderDescribe(),
			Query:           s.rsession.SetuppedQuery(),
		})

		s.mutex.Lock()
		s.state = gortsplib.ServerSessionStatePlay
		s.transport = s.rsession.SetuppedTransport()
		s.mutex.Unlock()
	}

	return &base.Response{
		StatusCode: base.StatusOK,
		Header:     h,
	}, nil
}

// onRecord is called by rtspServer.
func (s *session) onRecord(_ *gortsplib.ServerHandlerOnRecordCtx) (*base.Response, error) {
	if s.sentryManager != nil {
		desc := s.rsession.AnnouncedDescription()
		s.sentryManager.TraceConnectionEvent(s.sentrySpan, "record_started", map[string]interface{}{
			"session_id":  s.sessionID,
			"path":        s.pathName,
			"media_count": len(desc.Medias),
			"medias_info": defs.MediasInfo(desc.Medias),
			"transport":   s.rsession.SetuppedTransport().String(),
			"state":       "Record",
		})

		s.sentryManager.AddBreadcrumb("RTSP RECORD started", "rtsp_action", sentry.LevelInfo, map[string]interface{}{
			"session_id":  s.sessionID,
			"path":        s.pathName,
			"media_count": len(desc.Medias),
			"action":      "RECORD",
		})
	}

	stream, err := s.path.StartPublisher(defs.PathStartPublisherReq{
		Author:             s,
		Desc:               s.rsession.AnnouncedDescription(),
		GenerateRTPPackets: false,
	})
	if err != nil {
		if s.sentryManager != nil {
			s.sentryManager.TraceConnectionEvent(s.sentrySpan, "record_failed", map[string]interface{}{
				"session_id": s.sessionID,
				"path":       s.pathName,
				"error":      err.Error(),
			})

			s.sentryManager.CaptureError(err, map[string]string{
				"component":  "rtsp_session",
				"session_id": s.sessionID,
				"path":       s.pathName,
				"action":     "RECORD",
			})
		}

		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, err
	}

	s.stream = stream

	rtsp.ToStream(
		s.rsession,
		s.rsession.AnnouncedDescription().Medias,
		s.path.SafeConf(),
		stream,
		s)

	s.mutex.Lock()
	s.state = gortsplib.ServerSessionStateRecord
	s.transport = s.rsession.SetuppedTransport()
	s.mutex.Unlock()

	if s.sentryManager != nil {
		s.sentryManager.TraceConnectionEvent(s.sentrySpan, "record_success", map[string]interface{}{
			"session_id": s.sessionID,
			"path":       s.pathName,
			"transport":  s.rsession.SetuppedTransport().String(),
		})
	}

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// onPause is called by rtspServer.
func (s *session) onPause(_ *gortsplib.ServerHandlerOnPauseCtx) (*base.Response, error) {
	currentState := s.rsession.State()

	if s.sentryManager != nil {
		s.sentryManager.TraceConnectionEvent(s.sentrySpan, "pause_started", map[string]interface{}{
			"session_id":    s.sessionID,
			"path":          s.pathName,
			"current_state": currentState.String(),
		})

		s.sentryManager.AddBreadcrumb("RTSP PAUSE", "rtsp_action", sentry.LevelInfo, map[string]interface{}{
			"session_id": s.sessionID,
			"path":       s.pathName,
			"state":      currentState.String(),
			"action":     "PAUSE",
		})
	}

	switch currentState {
	case gortsplib.ServerSessionStatePlay:
		s.onUnreadHook()

		s.mutex.Lock()
		s.state = gortsplib.ServerSessionStatePrePlay
		s.mutex.Unlock()

		if s.sentryManager != nil {
			s.sentryManager.TraceConnectionEvent(s.sentrySpan, "pause_play_stopped", map[string]interface{}{
				"session_id": s.sessionID,
				"path":       s.pathName,
				"new_state":  "PrePlay",
			})
		}

	case gortsplib.ServerSessionStateRecord:
		s.path.StopPublisher(defs.PathStopPublisherReq{Author: s})

		s.mutex.Lock()
		s.state = gortsplib.ServerSessionStatePreRecord
		s.mutex.Unlock()

		if s.sentryManager != nil {
			s.sentryManager.TraceConnectionEvent(s.sentrySpan, "pause_record_stopped", map[string]interface{}{
				"session_id": s.sessionID,
				"path":       s.pathName,
				"new_state":  "PreRecord",
			})
		}
	}

	return &base.Response{
		StatusCode: base.StatusOK,
	}, nil
}

// APIReaderDescribe implements reader.
func (s *session) APIReaderDescribe() defs.APIPathSourceOrReader {
	return defs.APIPathSourceOrReader{
		Type: func() string {
			if s.isTLS {
				return "rtspsSession"
			}
			return "rtspSession"
		}(),
		ID: s.uuid.String(),
	}
}

// APISourceDescribe implements source.
func (s *session) APISourceDescribe() defs.APIPathSourceOrReader {
	return s.APIReaderDescribe()
}

// onPacketLost is called by rtspServer.
func (s *session) onPacketsLost(ctx *gortsplib.ServerHandlerOnPacketsLostCtx) {
	s.packetsLost.Add(ctx.Lost)
}

// onDecodeError is called by rtspServer.
func (s *session) onDecodeError(_ *gortsplib.ServerHandlerOnDecodeErrorCtx) {
	s.decodeErrors.Increase()
}

// onStreamWriteError is called by rtspServer.
func (s *session) onStreamWriteError(_ *gortsplib.ServerHandlerOnStreamWriteErrorCtx) {
	// currently the only error returned by OnStreamWriteError is ErrServerWriteQueueFull
	s.discardedFrames.Increase()
}

func (s *session) apiItem() *defs.APIRTSPSession {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	stats := s.rsession.Stats()

	return &defs.APIRTSPSession{
		ID:         s.uuid,
		Created:    s.created,
		RemoteAddr: s.remoteAddr().String(),
		State: func() defs.APIRTSPSessionState {
			switch s.state {
			case gortsplib.ServerSessionStatePrePlay,
				gortsplib.ServerSessionStatePlay:
				return defs.APIRTSPSessionStateRead

			case gortsplib.ServerSessionStatePreRecord,
				gortsplib.ServerSessionStateRecord:
				return defs.APIRTSPSessionStatePublish
			}
			return defs.APIRTSPSessionStateIdle
		}(),
		Path:  s.pathName,
		Query: s.query,
		Transport: func() *string {
			if s.transport == nil {
				return nil
			}
			v := s.transport.String()
			return &v
		}(),
		BytesReceived:       stats.BytesReceived,
		BytesSent:           stats.BytesSent,
		RTPPacketsReceived:  stats.RTPPacketsReceived,
		RTPPacketsSent:      stats.RTPPacketsSent,
		RTPPacketsLost:      stats.RTPPacketsLost,
		RTPPacketsInError:   stats.RTPPacketsInError,
		RTPPacketsJitter:    stats.RTPPacketsJitter,
		RTCPPacketsReceived: stats.RTCPPacketsReceived,
		RTCPPacketsSent:     stats.RTCPPacketsSent,
		RTCPPacketsInError:  stats.RTCPPacketsInError,
	}
}
