package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const defaultHTTPProxyListenAddr = "0.0.0.0:8081"

type HTTPProxyServer struct {
	logger       *log.Logger
	listenAddr   string
	listener     net.Listener
	server       *http.Server
	allowConnect func() bool
}

func newHTTPProxyServer(logger *log.Logger, listenAddr string, allowConnect func() bool) (*HTTPProxyServer, error) {
	if listenAddr == "" {
		listenAddr = defaultHTTPProxyListenAddr
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("启动 HTTP 代理监听失败: %w", err)
	}

	s := &HTTPProxyServer{
		logger:       logger,
		listenAddr:   listenAddr,
		listener:     listener,
		allowConnect: allowConnect,
	}

	s.server = &http.Server{
		Handler:           http.HandlerFunc(s.handleHTTP),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := s.server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Printf("HTTP 代理服务异常退出：%v", err)
		}
	}()

	logger.Printf("HTTP 代理监听已启动：%s", listener.Addr().String())
	return s, nil
}

func (s *HTTPProxyServer) ListenAddr() string {
	return s.listenAddr
}

func (s *HTTPProxyServer) Close() error {
	if s.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}

func (s *HTTPProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	s.logger.Printf("HTTP 代理请求：%s %s", r.Method, r.Host)

	if s.allowConnect != nil && !s.allowConnect() {
		http.Error(w, "当前 VPN 未连接，HTTP 代理暂不可用", http.StatusServiceUnavailable)
		return
	}

	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}

	if err := s.handleForward(w, r); err != nil {
		s.logger.Printf("HTTP 代理转发失败：%v", err)
		http.Error(w, "HTTP 代理转发失败", http.StatusBadGateway)
	}
}

func (s *HTTPProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.Host)
	if target == "" {
		http.Error(w, "HTTP CONNECT 缺少目标地址", http.StatusBadRequest)
		return
	}
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	remoteConn, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		http.Error(w, "连接目标失败", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = remoteConn.Close()
		http.Error(w, "当前 HTTP 服务不支持连接劫持", http.StatusInternalServerError)
		return
	}

	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		_ = remoteConn.Close()
		http.Error(w, "建立 HTTP 隧道失败", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()
	defer remoteConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Forward any bytes already buffered by the HTTP server before switching to raw relay.
	if buf != nil {
		if buffered := buf.Reader.Buffered(); buffered > 0 {
			_, _ = io.CopyN(remoteConn, buf, int64(buffered))
		}
	}

	errCh := make(chan error, 2)
	go relayTCP(errCh, remoteConn, clientConn)
	go relayTCP(errCh, clientConn, remoteConn)
	<-errCh
	<-errCh
}

func (s *HTTPProxyServer) handleForward(w http.ResponseWriter, r *http.Request) error {
	targetURL := r.URL
	if targetURL == nil {
		return fmt.Errorf("HTTP 代理请求缺少目标 URL")
	}
	if targetURL.Scheme == "" || targetURL.Host == "" {
		return fmt.Errorf("HTTP 代理仅支持携带绝对 URL 的请求")
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.Host = ""
	removeHopByHopHeaders(outReq.Header)

	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return err
}

func removeHopByHopHeaders(header http.Header) {
	for _, key := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(key)
	}
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
