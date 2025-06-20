package hls

import (
	_ "embed"
	"errors"
	"net"
	"net/http"
	gopath "path"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/gin-gonic/gin"

	"github.com/bluenviron/mediamtx/internal/auth"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/logger"
	"github.com/bluenviron/mediamtx/internal/protocols/httpp"
	"github.com/bluenviron/mediamtx/internal/restrictnetwork"
	internalSentry "github.com/bluenviron/mediamtx/internal/sentry"
)

//go:generate go run ./hlsjsdownloader

//go:embed index.html
var hlsIndex []byte

//go:embed hls.min.js
var hlsMinJS []byte

func mergePathAndQuery(path string, rawQuery string) string {
	res := path
	if rawQuery != "" {
		res += "?" + rawQuery
	}
	return res
}

type httpServer struct {
	address        string
	encryption     bool
	serverKey      string
	serverCert     string
	allowOrigin    string
	trustedProxies conf.IPNetworks
	readTimeout    conf.Duration
	pathManager    serverPathManager
	parent         *Server
	sentryManager  *internalSentry.Manager

	inner *httpp.Server
}

func (s *httpServer) initialize() error {
	router := gin.New()
	router.SetTrustedProxies(s.trustedProxies.ToTrustedProxies()) //nolint:errcheck

	router.Use(s.middlewareOrigin)

	// Add Sentry tracing middleware
	if s.sentryManager != nil {
		router.Use(s.middlewareSentryTracing)
	}

	router.Use(s.onRequest)

	network, address := restrictnetwork.Restrict("tcp", s.address)

	s.inner = &httpp.Server{
		Network:     network,
		Address:     address,
		ReadTimeout: time.Duration(s.readTimeout),
		Encryption:  s.encryption,
		ServerCert:  s.serverCert,
		ServerKey:   s.serverKey,
		Handler:     router,
		Parent:      s,
	}
	err := s.inner.Initialize()
	if err != nil {
		return err
	}

	return nil
}

// Log implements logger.Writer.
func (s *httpServer) Log(level logger.Level, format string, args ...interface{}) {
	s.parent.Log(level, format, args...)
}

func (s *httpServer) close() {
	s.inner.Close()
}

func (s *httpServer) middlewareOrigin(ctx *gin.Context) {
	ctx.Header("Access-Control-Allow-Origin", s.allowOrigin)
	ctx.Header("Access-Control-Allow-Credentials", "true")

	// preflight requests
	if ctx.Request.Method == http.MethodOptions &&
		ctx.Request.Header.Get("Access-Control-Request-Method") != "" {
		ctx.Header("Access-Control-Allow-Methods", "OPTIONS, GET")
		ctx.Header("Access-Control-Allow-Headers", "Authorization, Range")
		ctx.AbortWithStatus(http.StatusNoContent)
		return
	}
}

// middlewareSentryTracing adds Sentry transaction tracing for HTTP requests
func (s *httpServer) middlewareSentryTracing(ctx *gin.Context) {
	if s.sentryManager == nil {
		ctx.Next()
		return
	}

	startTime := time.Now()
	userAgent := ctx.Request.UserAgent()
	remoteAddr := httpp.RemoteAddr(ctx)

	// Start Sentry transaction
	span := s.sentryManager.StartHTTPTransaction(ctx.Request.Context(), ctx.Request.Method, ctx.Request.URL.Path, userAgent, remoteAddr)
	if span != nil {
		defer func() {
			responseTime := time.Since(startTime).Nanoseconds() / 1000000 // Convert to milliseconds
			statusCode := ctx.Writer.Status()

			s.sentryManager.TraceHTTPRequest(span, ctx.Request.Method, ctx.Request.URL.Path, userAgent, statusCode, responseTime, map[string]interface{}{
				"query":        ctx.Request.URL.RawQuery,
				"content_type": ctx.Request.Header.Get("Content-Type"),
				"referer":      ctx.Request.Header.Get("Referer"),
				"protocol":     "HLS",
			})

			s.sentryManager.AddBreadcrumb("HLS HTTP request", "http_request", sentry.LevelInfo, map[string]interface{}{
				"method":        ctx.Request.Method,
				"path":          ctx.Request.URL.Path,
				"status_code":   statusCode,
				"response_time": responseTime,
				"user_agent":    userAgent,
				"remote_addr":   remoteAddr,
			})

			span.Finish()
		}()
	}

	ctx.Next()
}

func (s *httpServer) onRequest(ctx *gin.Context) {
	if ctx.Request.Method != http.MethodGet {
		return
	}

	// remove leading prefix
	pa := ctx.Request.URL.Path[1:]

	var dir string
	var fname string

	switch {
	case strings.HasSuffix(pa, "/hls.min.js"):
		ctx.Header("Cache-Control", "max-age=3600")
		ctx.Header("Content-Type", "application/javascript")
		ctx.Writer.WriteHeader(http.StatusOK)
		ctx.Writer.Write(hlsMinJS)
		return

	case pa == "", pa == "favicon.ico", strings.HasSuffix(pa, "/hls.min.js.map"):
		return

	case strings.HasSuffix(pa, ".m3u8") ||
		strings.HasSuffix(pa, ".ts") ||
		strings.HasSuffix(pa, ".mp4") ||
		strings.HasSuffix(pa, ".mp"):
		dir, fname = gopath.Dir(pa), gopath.Base(pa)

		if strings.HasSuffix(fname, ".mp") {
			fname += "4"
		}

	default:
		dir, fname = pa, ""

		if !strings.HasSuffix(dir, "/") {
			ctx.Header("Location", mergePathAndQuery(ctx.Request.URL.Path+"/", ctx.Request.URL.RawQuery))
			ctx.Writer.WriteHeader(http.StatusMovedPermanently)
			return
		}
	}

	dir = strings.TrimSuffix(dir, "/")
	if dir == "" {
		return
	}

	req := defs.PathAccessRequest{
		Name:        dir,
		Query:       ctx.Request.URL.RawQuery,
		Publish:     false,
		Proto:       auth.ProtocolHLS,
		Credentials: httpp.Credentials(ctx.Request),
		IP:          net.ParseIP(ctx.ClientIP()),
	}

	pathConf, err := s.pathManager.FindPathConf(defs.PathFindPathConfReq{
		AccessRequest: req,
	})
	if err != nil {
		var terr auth.Error
		if errors.As(err, &terr) {
			if terr.AskCredentials {
				ctx.Header("WWW-Authenticate", `Basic realm="mediamtx"`)
				ctx.Writer.WriteHeader(http.StatusUnauthorized)
				return
			}

			s.Log(logger.Info, "connection %v failed to authenticate: %v", httpp.RemoteAddr(ctx), terr.Message)

			// wait some seconds to mitigate brute force attacks
			<-time.After(auth.PauseAfterError)

			ctx.Writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctx.Writer.WriteHeader(http.StatusNotFound)
		return
	}

	switch fname {
	case "":
		ctx.Header("Cache-Control", "max-age=3600")
		ctx.Header("Content-Type", "text/html")
		ctx.Writer.WriteHeader(http.StatusOK)
		ctx.Writer.Write(hlsIndex)

	default:
		mux, err := s.parent.getMuxer(serverGetMuxerReq{
			path:           dir,
			remoteAddr:     httpp.RemoteAddr(ctx),
			query:          ctx.Request.URL.RawQuery,
			sourceOnDemand: pathConf.SourceOnDemand,
		})
		if err != nil {
			ctx.Writer.WriteHeader(http.StatusNotFound)
			return
		}

		mi := mux.getInstance()
		if mi == nil {
			ctx.Writer.WriteHeader(http.StatusNotFound)
			return
		}

		ctx.Request.URL.Path = fname
		mi.handleRequest(ctx)
	}
}
