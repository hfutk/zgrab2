package http

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/http/webclassify"
)

// webClassifyTestServer is a minimal HTTP server that answers every connection
// with a canned response, so the full scanner stack (real dialer group,
// lib/http client, body decoding, web classification hook) is exercised.
// It counts accepted TCP connections so tests can assert the
// single-connection guarantee.
type webClassifyTestServer struct {
	listener net.Listener
	response string
	conns    atomic.Int32
}

func startWebClassifyTestServer(t *testing.T, response string) *webClassifyTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &webClassifyTestServer{listener: ln, response: response}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			srv.conns.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				// consume the request head
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				c.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprint(c, response)
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return srv
}

func httpResp(status string, headers []string, body string) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + status + "\r\n")
	b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)))
	b.WriteString(body)
	return b.String()
}

func runClassifyWebScan(t *testing.T, flags *Flags, response string) (*webClassifyTestServer, zgrab2.ScanStatus, *Results) {
	t.Helper()
	srv := startWebClassifyTestServer(t, response)
	scanner := NewModule().NewScanner().(*Scanner)
	flags.Port = uint(lport(t, srv.listener.Addr().String()))
	flags.ConnectTimeout = 5 * time.Second
	if err := scanner.Init(flags); err != nil {
		t.Fatalf("scanner.Init: %v", err)
	}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: flags.Port}
	dialerGroup, err := scanner.DialerGroupConfig.GetDefaultDialerGroupFromConfig()
	if err != nil {
		t.Fatalf("dialer group: %v", err)
	}
	status, res, _ := scanner.Scan(context.Background(), dialerGroup, target)
	results, _ := res.(*Results)
	if results == nil {
		t.Fatalf("nil results (status %s)", status)
	}
	return srv, status, results
}

func lport(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	var port int
	fmt.Sscanf(p, "%d", &port)
	return port
}

func baseClassifyWebFlags() *Flags {
	f := NewModule().NewFlags().(*Flags)
	// Field defaults from the zflags tags only apply during CLI parsing, so
	// set them explicitly here.
	f.Method = "GET"
	f.Endpoint = "/"
	f.MaxSize = 256
	f.MaxRedirects = 0
	f.UserAgent = "Mozilla/5.0 zgrab/0.x"
	f.ClassifyWeb = true
	return f
}

// requireLabel asserts the core label semantics: whatever the classification
// verdict is, the scan status stays "success" — the classification block is pure
// metadata, zgrab2 never drops targets.
func requireLabel(t *testing.T, status zgrab2.ScanStatus, results *Results, matched bool, category webclassify.Category, rule string) {
	t.Helper()
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %s, want success (classification must never change the scan status)", status)
	}
	wf := results.Classification
	if wf == nil {
		t.Fatal("classification block missing")
	}
	if wf.Matched != matched {
		t.Fatalf("matched = %v, want %v", wf.Matched, matched)
	}
	if wf.Category != category {
		t.Fatalf("category = %s, want %s", wf.Category, category)
	}
	if matched && wf.Rule != rule {
		t.Fatalf("rule = %s, want %s", wf.Rule, rule)
	}
}

func TestWebClassificationBusinessPage(t *testing.T) {
	_, status, results := runClassifyWebScan(t, baseClassifyWebFlags(),
		httpResp("200 OK", nil, "<html><head><title>某公司业务系统</title></head><body>登录</body></html>"))
	requireLabel(t, status, results, false, webclassify.CategoryBusiness, "")
}

func TestWebClassificationNginxDefaultLabeled(t *testing.T) {
	_, status, results := runClassifyWebScan(t, baseClassifyWebFlags(),
		httpResp("200 OK", []string{"Server: nginx/1.24.0"},
			"<html><head><title>Welcome to nginx!</title></head><body>If you see this page, the nginx web server is successfully installed.</body></html>"))
	// still a successful scan: the default-page verdict is only a label
	requireLabel(t, status, results, true, webclassify.CategoryDefault, "nginx_default")
}

func TestWebClassificationWAFLabeled(t *testing.T) {
	_, status, results := runClassifyWebScan(t, baseClassifyWebFlags(),
		httpResp("405 Not Allowed", nil,
			"<html><body>您的请求可能对网站造成威胁，已被Web应用防火墙拦截 <a href='https://errors.aliyun.com'>errors.aliyun.com</a></body></html>"))
	requireLabel(t, status, results, true, webclassify.CategoryWAF, "aliyun_waf")
}

func TestWebClassificationProxy407Labeled(t *testing.T) {
	_, status, results := runClassifyWebScan(t, baseClassifyWebFlags(),
		httpResp("407 Proxy Authentication Required", []string{"Proxy-Authenticate: Basic realm=\"proxy\""}, "auth pls"))
	requireLabel(t, status, results, true, webclassify.CategoryProxy, "http_407")
}

func TestWebClassificationPanelLabeled(t *testing.T) {
	_, status, results := runClassifyWebScan(t, baseClassifyWebFlags(),
		httpResp("200 OK", nil, "<html><head><title>宝塔Linux面板 - 安全入口</title></head><body>BT-Panel</body></html>"))
	requireLabel(t, status, results, true, webclassify.CategoryPanel, "bt_panel")
}

func TestWebClassificationCloudflareCDNLabeled(t *testing.T) {
	_, status, results := runClassifyWebScan(t, baseClassifyWebFlags(),
		httpResp("403 Forbidden", []string{"Server: cloudflare", "Cf-Ray: 8f3a2b1c0d9e0123-LAX"},
			"<html><body>Attention Required! | Cloudflare<br>Ray ID: 8f3a2b1c0d9e0123</body></html>"))
	requireLabel(t, status, results, true, webclassify.CategoryCDN, "cloudflare")
}

// TestWebClassificationDisabledByDefault verifies that without --classify-web the
// results carry no classification block at all.
func TestWebClassificationDisabledByDefault(t *testing.T) {
	f := baseClassifyWebFlags()
	f.ClassifyWeb = false
	_, status, results := runClassifyWebScan(t, f,
		httpResp("200 OK", nil, "<html><head><title>Welcome to nginx!</title></head></html>"))
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %s, want success", status)
	}
	if results.Classification != nil {
		t.Fatalf("classification = %+v, want nil without --classify-web", results.Classification)
	}
}

// TestWebClassificationSingleConnection verifies the single-connection
// guarantee: with default flags (no redirects, no HTTPS retry), a scan with
// classification enabled opens exactly one TCP connection and issues one
// request — the label is derived from that response alone, in-process.
func TestWebClassificationSingleConnection(t *testing.T) {
	srv, status, results := runClassifyWebScan(t, baseClassifyWebFlags(),
		httpResp("403 Forbidden", []string{"Server: cloudflare"},
			"<html><body>Attention Required! | Cloudflare</body></html>"))
	requireLabel(t, status, results, true, webclassify.CategoryCDN, "cloudflare")
	if n := srv.conns.Load(); n != 1 {
		t.Fatalf("scan used %d TCP connections, want exactly 1 (classification must not add connections)", n)
	}
}

// TestWebClassificationRedirectNotFollowed verifies that a 3xx response is
// labeled as-is: by default the scanner does not follow redirects (that
// would need extra connections), so the classification describes the
// redirect response the origin itself returned.
func TestWebClassificationRedirectNotFollowed(t *testing.T) {
	srv, status, results := runClassifyWebScan(t, baseClassifyWebFlags(),
		httpResp("301 Moved Permanently", []string{"Location: https://example.com/"}, ""))
	requireLabel(t, status, results, false, webclassify.CategoryBusiness, "")
	if n := srv.conns.Load(); n != 1 {
		t.Fatalf("redirect scan used %d TCP connections, want exactly 1 (redirects must not be followed by default)", n)
	}
}
