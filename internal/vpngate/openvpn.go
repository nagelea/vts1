package vpngate

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"
)

const (
	OpenVPNSuccessMarker        = "Initialization Sequence Completed"
	openVPNExecutable           = "openvpn"
	openVPNLogTailLimit         = 80
	defaultOpenVPNTestTimeout   = 12 * time.Second
	defaultTCPPrecheckTimeout   = 3 * time.Second
	defaultTCPPrecheckKeepAlive = 15 * time.Second
)

type OpenVPNLaunch struct {
	Executable string
	ConfigText string
	Cipher     string
	Protocol   string
	RemoteHost string
	RemotePort string
}

type OpenVPNTestResult struct {
	Success  bool          `json:"success"`
	Duration time.Duration `json:"duration"`
	Detail   string        `json:"detail"`
}

func PrepareOpenVPNLaunch(server Server) (OpenVPNLaunch, error) {
	configText, err := decodeOpenVPNConfig(server.OpenVPNConfigDataBase64)
	if err != nil {
		return OpenVPNLaunch{}, err
	}

	return OpenVPNLaunch{
		Executable: openVPNExecutable,
		ConfigText: normalizeOpenVPNConfig(configText),
		Cipher:     detectLegacyCipher(configText),
		Protocol:   detectRemoteProtocol(configText),
		RemoteHost: detectRemoteHost(configText),
		RemotePort: detectRemotePort(configText),
	}, nil
}

func BuildOpenVPNConnectArgs(configPath, cipher string) []string {
	args := []string{
		"--config", configPath,
		"--auth-nocache",
		"--verb", "3",
		"--connect-retry-max", "1",
		"--connect-timeout", "20",
	}

	if strings.TrimSpace(cipher) != "" {
		args = append(args, "--data-ciphers", buildDataCiphers(cipher))
		args = append(args, "--data-ciphers-fallback", strings.TrimSpace(cipher))
	}

	return args
}

func TestServerWithOpenVPN(ctx context.Context, server Server) (OpenVPNTestResult, error) {
	if ctx == nil {
		baseCtx := context.Background()
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(baseCtx, defaultOpenVPNTestTimeout)
		defer cancel()
	}

	start := time.Now()
	launch, err := PrepareOpenVPNLaunch(server)
	if err != nil {
		return OpenVPNTestResult{}, err
	}

	if shouldRunTCPPrecheck(launch) {
		if err := runTCPPrecheck(ctx, launch.RemoteHost, launch.RemotePort); err != nil {
			return OpenVPNTestResult{}, err
		}
	}

	tmpFile, err := os.CreateTemp("", "vpngate-openvpn-test-*.ovpn")
	if err != nil {
		return OpenVPNTestResult{}, fmt.Errorf("创建 OpenVPN 测试配置文件失败: %w", err)
	}
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()

	if _, err := io.WriteString(tmpFile, launch.ConfigText); err != nil {
		_ = tmpFile.Close()
		return OpenVPNTestResult{}, fmt.Errorf("写入 OpenVPN 测试配置文件失败: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return OpenVPNTestResult{}, fmt.Errorf("关闭 OpenVPN 测试配置文件失败: %w", err)
	}

	args := buildOpenVPNTestArgs(tmpFile.Name(), launch.Cipher)
	cmd := exec.CommandContext(ctx, launch.Executable, args...)

	reader, writer := io.Pipe()
	cmd.Stdout = writer
	cmd.Stderr = writer

	successCh := make(chan struct{}, 1)
	scanDone := make(chan openVPNScanResult, 1)
	go func() {
		scanDone <- scanOpenVPNOutput(reader, successCh)
	}()

	if err := cmd.Start(); err != nil {
		_ = writer.Close()
		scanResult := <-scanDone
		detail := summarizeWithScanError(scanResult)
		if detail != "" {
			return OpenVPNTestResult{}, fmt.Errorf("启动 openvpn 失败: %s", detail)
		}
		return OpenVPNTestResult{}, fmt.Errorf("启动 openvpn 失败: %w", err)
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cmd.Wait()
	}()

	for {
		select {
		case <-successCh:
			stopOpenVPNProcess(cmd)
			waitErr := <-waitDone
			_ = writer.Close()
			scanResult := <-scanDone
			if scanResult.err != nil {
				return OpenVPNTestResult{}, fmt.Errorf("读取 OpenVPN 日志失败: %w", scanResult.err)
			}
			if !containsSuccessMarker(scanResult.lines) && waitErr != nil {
				return OpenVPNTestResult{}, fmt.Errorf("OpenVPN 测试失败: %s", summarizeWithScanError(scanResult))
			}

			return OpenVPNTestResult{
				Success:  true,
				Duration: time.Since(start),
				Detail:   "OpenVPN 握手成功并已主动断开",
			}, nil

		case waitErr := <-waitDone:
			_ = writer.Close()
			scanResult := <-scanDone
			if scanResult.err != nil {
				return OpenVPNTestResult{}, fmt.Errorf("读取 OpenVPN 日志失败: %w", scanResult.err)
			}
			if containsSuccessMarker(scanResult.lines) {
				return OpenVPNTestResult{
					Success:  true,
					Duration: time.Since(start),
					Detail:   "OpenVPN 握手成功并已自动退出",
				}, nil
			}

			detail := summarizeWithScanError(scanResult)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return OpenVPNTestResult{}, fmt.Errorf("OpenVPN 测试超时: %s", safeFailureDetail(detail, "超过等待时间仍未完成握手"))
			}
			if errors.Is(ctx.Err(), context.Canceled) {
				return OpenVPNTestResult{}, fmt.Errorf("OpenVPN 测试已取消: %s", safeFailureDetail(detail, "调用方已取消测试"))
			}
			if waitErr != nil {
				return OpenVPNTestResult{}, fmt.Errorf("OpenVPN 测试失败: %s", safeFailureDetail(detail, waitErr.Error()))
			}

			return OpenVPNTestResult{}, fmt.Errorf("OpenVPN 测试失败: %s", safeFailureDetail(detail, "OpenVPN 进程已退出"))

		case <-ctx.Done():
			stopOpenVPNProcess(cmd)
			waitErr := <-waitDone
			_ = writer.Close()
			scanResult := <-scanDone
			detail := summarizeWithScanError(scanResult)
			if containsSuccessMarker(scanResult.lines) {
				return OpenVPNTestResult{
					Success:  true,
					Duration: time.Since(start),
					Detail:   "OpenVPN 握手成功并在结束前收到取消信号",
				}, nil
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return OpenVPNTestResult{}, fmt.Errorf("OpenVPN 测试超时: %s", safeFailureDetail(detail, "超过等待时间仍未完成握手"))
			}
			if waitErr != nil {
				return OpenVPNTestResult{}, fmt.Errorf("OpenVPN 测试已取消: %s", safeFailureDetail(detail, waitErr.Error()))
			}
			return OpenVPNTestResult{}, fmt.Errorf("OpenVPN 测试已取消: %s", safeFailureDetail(detail, "调用方已取消测试"))
		}
	}
}

func SummarizeOpenVPNFailure(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		if detail, ok := summarizeSpecificOpenVPNFailure(line); ok {
			return detail
		}
	}

	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		upper := strings.ToUpper(line)
		switch {
		case strings.Contains(upper, "FATAL"):
			return line
		case strings.Contains(upper, "ERROR"):
			return line
		}
	}

	if len(lines) == 0 {
		return ""
	}

	return strings.TrimSpace(lines[len(lines)-1])
}

func summarizeSpecificOpenVPNFailure(line string) (string, bool) {
	upper := strings.ToUpper(strings.TrimSpace(line))
	switch {
	case strings.Contains(upper, "AUTH_FAILED"):
		return "OpenVPN 认证失败", true
	case strings.Contains(upper, "FAILED TO NEGOTIATE CIPHER"):
		return "OpenVPN 数据加密算法协商失败", true
	case strings.Contains(upper, "HOST IS UNREACHABLE"):
		return "目标节点不可达", true
	case strings.Contains(upper, "TLS KEY NEGOTIATION FAILED"):
		return "TLS 密钥协商失败", true
	case strings.Contains(upper, "TLS ERROR"):
		return "TLS 握手失败", true
	case strings.Contains(upper, "CONNECTION TIMED OUT"):
		return "连接目标节点超时", true
	case strings.Contains(upper, "INACTIVITY TIMEOUT"):
		return "连接空闲超时", true
	case strings.Contains(upper, "NETWORK IS UNREACHABLE"):
		return "网络不可达，无法连接目标节点", true
	case strings.Contains(upper, "CANNOT OPEN TUN/TAP DEV"):
		return "无法打开 TUN/TAP 设备，请检查容器权限或宿主机网络能力", true
	case strings.Contains(upper, "PERMISSION DENIED"):
		return "权限不足，无法启动 OpenVPN 或配置网络", true
	case strings.Contains(upper, "OPTIONS ERROR"):
		return "OpenVPN 配置存在错误", true
	case strings.Contains(upper, "RESOLVE") && strings.Contains(upper, "FAILED"):
		return "解析 VPN 节点地址失败", true
	case strings.Contains(upper, "CONNECTION-FAILED"):
		return "连接目标节点失败", true
	default:
		return "", false
	}
}

func ShouldAbortConnectOnLine(line string) bool {
	upper := strings.ToUpper(strings.TrimSpace(line))
	if upper == "" {
		return false
	}

	return strings.Contains(upper, "FAILED TO NEGOTIATE CIPHER") ||
		strings.Contains(upper, "CONNECTION-FAILED") ||
		strings.Contains(upper, "HOST IS UNREACHABLE") ||
		strings.Contains(upper, "NETWORK IS UNREACHABLE") ||
		strings.Contains(upper, "AUTH_FAILED") ||
		strings.Contains(upper, "TLS ERROR") ||
		strings.Contains(upper, "TLS KEY NEGOTIATION FAILED")
}

func buildDataCiphers(cipher string) string {
	base := []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}
	normalized := strings.TrimSpace(cipher)
	if normalized == "" {
		return strings.Join(base, ":")
	}
	if !slices.Contains(base, normalized) {
		base = append(base, normalized)
	}

	return strings.Join(base, ":")
}

func shouldRunTCPPrecheck(launch OpenVPNLaunch) bool {
	if strings.TrimSpace(launch.RemoteHost) == "" || strings.TrimSpace(launch.RemotePort) == "" {
		return false
	}

	protocol := strings.ToLower(strings.TrimSpace(launch.Protocol))
	return strings.HasPrefix(protocol, "tcp")
}

func runTCPPrecheck(ctx context.Context, host, port string) error {
	timeout := defaultTCPPrecheckTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("TCP 预检失败：测试已超时")
		}
		if remaining < timeout {
			timeout = remaining
		}
	}

	target := net.JoinHostPort(strings.TrimSpace(host), strings.TrimSpace(port))
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: defaultTCPPrecheckKeepAlive,
	}
	precheckCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(precheckCtx, "tcp", target)
	if err != nil {
		return fmt.Errorf("TCP 预检失败：%s", summarizeTCPPrecheckError(err))
	}
	_ = conn.Close()
	return nil
}

func summarizeTCPPrecheckError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "连接目标节点超时"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "连接目标节点超时"
	}

	message := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(message, "host is unreachable"), strings.Contains(message, "no route to host"):
		return "目标节点不可达"
	case strings.Contains(message, "network is unreachable"):
		return "网络不可达，无法连接目标节点"
	case strings.Contains(message, "connection refused"):
		return "目标节点拒绝连接"
	default:
		return err.Error()
	}
}

type openVPNScanResult struct {
	lines []string
	err   error
}

func buildOpenVPNTestArgs(configPath, cipher string) []string {
	args := BuildOpenVPNConnectArgs(configPath, cipher)
	args = append(args,
		"--route-noexec",
		"--ifconfig-noexec",
		"--pull-filter", "ignore", "redirect-gateway",
		"--pull-filter", "ignore", "dhcp-option",
	)

	return args
}

func scanOpenVPNOutput(reader io.Reader, successCh chan<- struct{}) openVPNScanResult {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), maxIPhoneResponseBytes)

	lines := make([]string, 0, openVPNLogTailLimit)
	successSent := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		lines = append(lines, line)
		if len(lines) > openVPNLogTailLimit {
			lines = append([]string(nil), lines[len(lines)-openVPNLogTailLimit:]...)
		}

		if !successSent && strings.Contains(line, OpenVPNSuccessMarker) {
			successSent = true
			if successCh != nil {
				successCh <- struct{}{}
			}
		}
	}

	return openVPNScanResult{lines: lines, err: scanner.Err()}
}

func summarizeWithScanError(result openVPNScanResult) string {
	detail := SummarizeOpenVPNFailure(result.lines)
	if result.err == nil {
		return detail
	}
	if detail == "" {
		return fmt.Sprintf("读取 OpenVPN 日志失败: %v", result.err)
	}

	return detail + " | 读取 OpenVPN 日志失败: " + result.err.Error()
}

func containsSuccessMarker(lines []string) bool {
	for _, line := range lines {
		if strings.Contains(line, OpenVPNSuccessMarker) {
			return true
		}
	}

	return false
}

func safeFailureDetail(detail, fallback string) string {
	if strings.TrimSpace(detail) != "" {
		return detail
	}

	return fallback
}

func stopOpenVPNProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		_ = cmd.Process.Kill()
	}
}

func decodeOpenVPNConfig(encoded string) (string, error) {
	trimmed := compactWhitespace(encoded)
	if trimmed == "" {
		return "", fmt.Errorf("缺少 OpenVPN 配置数据")
	}

	payload, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		payload, err = base64.RawStdEncoding.DecodeString(trimmed)
		if err != nil {
			return "", fmt.Errorf("解码 OpenVPN 配置失败: %w", err)
		}
	}

	return string(payload), nil
}

func compactWhitespace(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for _, r := range value {
		switch r {
		case ' ', '\n', '\r', '\t':
			continue
		default:
			builder.WriteRune(r)
		}
	}

	return builder.String()
}

func normalizeOpenVPNConfig(configText string) string {
	normalized := strings.ReplaceAll(configText, "\r\n", "\n")
	normalized = strings.TrimSpace(normalized)
	if normalized == "" {
		return ""
	}

	return normalized + "\n"
}

func detectLegacyCipher(configText string) string {
	scanner := bufio.NewScanner(strings.NewReader(configText))
	for scanner.Scan() {
		fields := parseOpenVPNConfigFields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if strings.EqualFold(fields[0], "cipher") {
			return fields[1]
		}
	}

	return ""
}

func detectRemoteProtocol(configText string) string {
	scanner := bufio.NewScanner(strings.NewReader(configText))
	for scanner.Scan() {
		fields := parseOpenVPNConfigFields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if strings.EqualFold(fields[0], "proto") {
			return fields[1]
		}
	}

	return ""
}

func detectRemoteHost(configText string) string {
	host, _ := detectRemoteEndpoint(configText)
	return host
}

func detectRemotePort(configText string) string {
	_, port := detectRemoteEndpoint(configText)
	return port
}

func detectRemoteEndpoint(configText string) (string, string) {
	scanner := bufio.NewScanner(strings.NewReader(configText))
	for scanner.Scan() {
		fields := parseOpenVPNConfigFields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if strings.EqualFold(fields[0], "remote") {
			return fields[1], fields[2]
		}
	}

	return "", ""
}

func parseOpenVPNConfigFields(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return nil
	}

	return strings.Fields(line)
}
