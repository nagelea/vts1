package vpngate

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	IPhoneAPIURL            = "https://www.vpngate.net/api/iphone/"
	iPhoneResponseStartMark = "*vpn_servers"
	iPhoneResponseEndMark   = "*"
	maxIPhoneResponseBytes  = 8 << 20
)

var expectedIPhoneHeader = []string{
	"HostName",
	"IP",
	"Score",
	"Ping",
	"Speed",
	"CountryLong",
	"CountryShort",
	"NumVpnSessions",
	"Uptime",
	"TotalUsers",
	"TotalTraffic",
	"LogType",
	"Operator",
	"Message",
	"OpenVPN_ConfigData_Base64",
}

type Server struct {
	HostName                string `json:"hostName"`
	IP                      string `json:"ip"`
	Score                   int64  `json:"score"`
	Ping                    int    `json:"ping"`
	Speed                   int64  `json:"speed"`
	CountryLong             string `json:"countryLong"`
	CountryShort            string `json:"countryShort"`
	NumVPNSessions          int64  `json:"numVPNSessions"`
	Uptime                  int64  `json:"uptime"`
	TotalUsers              int64  `json:"totalUsers"`
	TotalTraffic            int64  `json:"totalTraffic"`
	LogType                 string `json:"logType"`
	Operator                string `json:"operator"`
	Message                 string `json:"message"`
	OpenVPNConfigDataBase64 string `json:"openVPNConfigDataBase64"`
}

func FetchIPhoneServers(ctx context.Context, client *http.Client) ([]Server, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, IPhoneAPIURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建 VPN Gate 节点请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "vpngate-to-socks/1")
	req.Header.Set("Accept", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 VPN Gate 节点列表失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VPN Gate 节点接口返回异常状态: %s", resp.Status)
	}

	payload, err := readLimitedBody(resp.Body, maxIPhoneResponseBytes)
	if err != nil {
		return nil, err
	}

	servers, err := parseIPhoneResponse(payload)
	if err != nil {
		return nil, err
	}

	return servers, nil
}

func IsRecommendedServer(server Server) bool {
	if strings.TrimSpace(server.HostName) == "" || strings.TrimSpace(server.IP) == "" {
		return false
	}
	if strings.TrimSpace(server.OpenVPNConfigDataBase64) == "" {
		return false
	}
	if server.TotalUsers <= 0 {
		return false
	}
	if server.NumVPNSessions <= 0 {
		return false
	}

	return true
}

func SortServersByRecommendation(servers []Server) {
	sort.SliceStable(servers, func(i, j int) bool {
		left := servers[i]
		right := servers[j]

		leftRecommended := IsRecommendedServer(left)
		rightRecommended := IsRecommendedServer(right)
		if leftRecommended != rightRecommended {
			return leftRecommended
		}

		if left.TotalUsers != right.TotalUsers {
			return left.TotalUsers < right.TotalUsers
		}
		if left.Uptime != right.Uptime {
			return left.Uptime < right.Uptime
		}
		if left.NumVPNSessions != right.NumVPNSessions {
			return left.NumVPNSessions < right.NumVPNSessions
		}

		leftHasPing := left.Ping > 0
		rightHasPing := right.Ping > 0
		if leftHasPing != rightHasPing {
			return leftHasPing
		}
		if leftHasPing && left.Ping != right.Ping {
			return left.Ping < right.Ping
		}

		if left.Speed != right.Speed {
			return left.Speed > right.Speed
		}
		if left.Score != right.Score {
			return left.Score > right.Score
		}

		leftCountry := strings.ToUpper(strings.TrimSpace(left.CountryShort))
		rightCountry := strings.ToUpper(strings.TrimSpace(right.CountryShort))
		if leftCountry != rightCountry {
			return leftCountry < rightCountry
		}

		leftHost := strings.ToLower(strings.TrimSpace(left.HostName))
		rightHost := strings.ToLower(strings.TrimSpace(right.HostName))
		if leftHost != rightHost {
			return leftHost < rightHost
		}

		return strings.TrimSpace(left.IP) < strings.TrimSpace(right.IP)
	})
}

func parseIPhoneResponse(payload []byte) ([]Server, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(payload)))
	scanner.Buffer(make([]byte, 1024), maxIPhoneResponseBytes)

	var servers []Server
	startSeen := false
	headerSeen := false
	endSeen := false

	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if !startSeen {
			if stripUTF8BOM(line) != iPhoneResponseStartMark {
				return nil, fmt.Errorf("VPN Gate 响应首行不是 %q", iPhoneResponseStartMark)
			}
			startSeen = true
			continue
		}

		if !headerSeen {
			if !strings.HasPrefix(line, "#") {
				return nil, fmt.Errorf("VPN Gate 响应第 %d 行缺少表头", lineNo)
			}

			header, err := parseCSVRecord(strings.TrimPrefix(line, "#"))
			if err != nil {
				return nil, fmt.Errorf("解析 VPN Gate 响应表头失败: %w", err)
			}
			if err := validateHeader(header); err != nil {
				return nil, err
			}

			headerSeen = true
			continue
		}

		if line == iPhoneResponseEndMark {
			endSeen = true
			break
		}

		record, err := parseCSVRecord(line)
		if err != nil {
			return nil, fmt.Errorf("解析 VPN Gate 第 %d 行记录失败: %w", lineNo, err)
		}

		server, err := parseServerRecord(record, lineNo)
		if err != nil {
			return nil, err
		}
		servers = append(servers, server)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 VPN Gate 响应失败: %w", err)
	}
	if !startSeen {
		return nil, fmt.Errorf("VPN Gate 响应缺少起始标记 %q", iPhoneResponseStartMark)
	}
	if !headerSeen {
		return nil, fmt.Errorf("VPN Gate 响应缺少表头")
	}
	if !endSeen {
		return nil, fmt.Errorf("VPN Gate 响应缺少结束标记 %q", iPhoneResponseEndMark)
	}

	return servers, nil
}

func validateHeader(header []string) error {
	if len(header) != len(expectedIPhoneHeader) {
		return fmt.Errorf("VPN Gate 表头字段数错误: got %d, want %d", len(header), len(expectedIPhoneHeader))
	}

	for i, want := range expectedIPhoneHeader {
		got := strings.TrimSpace(header[i])
		if got != want {
			return fmt.Errorf("VPN Gate 表头第 %d 列错误: got %q, want %q", i+1, got, want)
		}
	}

	return nil
}

func parseServerRecord(record []string, lineNo int) (Server, error) {
	if len(record) != len(expectedIPhoneHeader) {
		return Server{}, fmt.Errorf("VPN Gate 第 %d 行字段数错误: got %d, want %d", lineNo, len(record), len(expectedIPhoneHeader))
	}

	score, err := parseInt64Field(record[2], lineNo, "Score")
	if err != nil {
		return Server{}, err
	}
	ping, err := parseIntField(record[3], lineNo, "Ping")
	if err != nil {
		return Server{}, err
	}
	speed, err := parseInt64Field(record[4], lineNo, "Speed")
	if err != nil {
		return Server{}, err
	}
	sessions, err := parseInt64Field(record[7], lineNo, "NumVpnSessions")
	if err != nil {
		return Server{}, err
	}
	uptime, err := parseInt64Field(record[8], lineNo, "Uptime")
	if err != nil {
		return Server{}, err
	}
	totalUsers, err := parseInt64Field(record[9], lineNo, "TotalUsers")
	if err != nil {
		return Server{}, err
	}
	totalTraffic, err := parseInt64Field(record[10], lineNo, "TotalTraffic")
	if err != nil {
		return Server{}, err
	}

	return Server{
		HostName:                strings.TrimSpace(record[0]),
		IP:                      strings.TrimSpace(record[1]),
		Score:                   score,
		Ping:                    ping,
		Speed:                   speed,
		CountryLong:             strings.TrimSpace(record[5]),
		CountryShort:            strings.TrimSpace(record[6]),
		NumVPNSessions:          sessions,
		Uptime:                  uptime,
		TotalUsers:              totalUsers,
		TotalTraffic:            totalTraffic,
		LogType:                 strings.TrimSpace(record[11]),
		Operator:                strings.TrimSpace(record[12]),
		Message:                 strings.TrimSpace(record[13]),
		OpenVPNConfigDataBase64: strings.TrimSpace(record[14]),
	}, nil
}

func parseCSVRecord(line string) ([]string, error) {
	reader := csv.NewReader(strings.NewReader(line))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = false

	record, err := reader.Read()
	if err != nil {
		return nil, err
	}

	return record, nil
}

func parseInt64Field(raw string, lineNo int, fieldName string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "-" {
		return 0, nil
	}

	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("VPN Gate 第 %d 行字段 %s 不是有效整数: %w", lineNo, fieldName, err)
	}

	return value, nil
}

func parseIntField(raw string, lineNo int, fieldName string) (int, error) {
	value, err := parseInt64Field(raw, lineNo, fieldName)
	if err != nil {
		return 0, err
	}

	return int(value), nil
}

func readLimitedBody(body io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("读取 VPN Gate 响应失败: %w", err)
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("VPN Gate 响应过大，超过 %d 字节限制", limit)
	}

	return payload, nil
}

func stripUTF8BOM(value string) string {
	return strings.TrimPrefix(value, "\ufeff")
}
