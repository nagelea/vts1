package vpngate

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	OpenVPNSuccessMarker = "Initialization Sequence Completed"
	openVPNExecutable    = "openvpn"
	openVPNLogTailLimit  = 80
)

type OpenVPNLaunch struct {
	Executable string
	ConfigText string
	Cipher     string
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
		args = append(args, "--data-ciphers-fallback", strings.TrimSpace(cipher))
	}

	return args
}

func TestServerWithOpenVPN(ctx context.Context, server Server) (OpenVPNTestResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	launch, err := PrepareOpenVPNLaunch(server)
	if err != nil {
		return OpenVPNTestResult{}, err
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

	start := time.Now()
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

		upper := strings.ToUpper(line)
		switch {
		case strings.Contains(upper, "AUTH_FAILED"):
			return "OpenVPN 认证失败"
		case strings.Contains(upper, "HOST IS UNREACHABLE"):
			return "目标节点不可达"
		case strings.Contains(upper, "TLS KEY NEGOTIATION FAILED"):
			return "TLS 密钥协商失败"
		case strings.Contains(upper, "TLS ERROR"):
			return "TLS 握手失败"
		case strings.Contains(upper, "CONNECTION TIMED OUT"):
			return "连接目标节点超时"
		case strings.Contains(upper, "INACTIVITY TIMEOUT"):
			return "连接空闲超时"
		case strings.Contains(upper, "NETWORK IS UNREACHABLE"):
			return "网络不可达，无法连接目标节点"
		case strings.Contains(upper, "CANNOT OPEN TUN/TAP DEV"):
			return "无法打开 TUN/TAP 设备，请检查容器权限或宿主机网络能力"
		case strings.Contains(upper, "PERMISSION DENIED"):
			return "权限不足，无法启动 OpenVPN 或配置网络"
		case strings.Contains(upper, "OPTIONS ERROR"):
			return "OpenVPN 配置存在错误"
		case strings.Contains(upper, "RESOLVE") && strings.Contains(upper, "FAILED"):
			return "解析 VPN 节点地址失败"
		case strings.Contains(upper, "CONNECTION-FAILED"):
			return "连接目标节点失败"
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

func ShouldAbortConnectOnLine(line string) bool {
	upper := strings.ToUpper(strings.TrimSpace(line))
	if upper == "" {
		return false
	}

	return strings.Contains(upper, "CONNECTION-FAILED") ||
		strings.Contains(upper, "HOST IS UNREACHABLE") ||
		strings.Contains(upper, "NETWORK IS UNREACHABLE") ||
		strings.Contains(upper, "AUTH_FAILED") ||
		strings.Contains(upper, "TLS ERROR") ||
		strings.Contains(upper, "TLS KEY NEGOTIATION FAILED")
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
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.EqualFold(fields[0], "cipher") {
			return fields[1]
		}
	}

	return ""
}
