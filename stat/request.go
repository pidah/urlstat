package stat

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/net/http2"
)

type Request struct {
	URL         *url.URL
	HTTPHeaders Headers

	HTTPMethod     string // default: GET
	PostBody       string
	ClientCertFile string

	FollowRedirects bool
	OnlyHeader      bool
	Insecure        bool
	ShowVersion     bool

	MaxRedirects int
}

func NewRequest(path string) *Request {
	return &Request{
		URL:             parseURL(path),
		HTTPMethod:      "GET",
		FollowRedirects: true,
		MaxRedirects:    2,
	}
}

func (r Request) visit(w *Response) {
	req := r.cook()

	var t0, t1, t2, t3, t4 time.Time

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { t0 = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { t1 = time.Now() },
		ConnectStart: func(_, _ string) {
			if t1.IsZero() {
				// connecting to IP
				t1 = time.Now()
			}
		},
		ConnectDone: func(net, addr string, err error) {
			if err != nil {
				makePanic("Unable to connect to host %v: %v", addr, err)
			}
			t2 = time.Now()

			w.report("Connected to %s\n", addr)
		},
		GotConn:              func(_ httptrace.GotConnInfo) { t3 = time.Now() },
		GotFirstResponseByte: func() { t4 = time.Now() },
	}

	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	switch r.URL.Scheme {
	case "https":
		host, _, err := net.SplitHostPort(req.Host)
		if err != nil {
			host = req.Host
		}

		tr.TLSClientConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: r.Insecure,
			Certificates:       readClientCert(r.ClientCertFile),
		}

		// Because we create a custom TLSClientConfig, we have to opt-in to HTTP/2.
		// See https://github.com/golang/go/issues/14275
		err = http2.ConfigureTransport(tr)
		if err != nil {
			makePanic("Failed to prepare transport for HTTP/2: %v", err)
		}
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// always refuse to follow redirects, visit does that
			// manually if required.
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		makePanic("Failed to read response: %v", err)
	}

	bodyMsg := readResponseBody(req, resp)
	resp.Body.Close()

	t5 := time.Now() // after read body
	if t0.IsZero() {
		// we skipped DNS
		t0 = t1
	}

	// print status line and headers
	w.report("HTTP/%d.%d %s", resp.ProtoMajor, resp.ProtoMinor, resp.Status)

	names := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		names = append(names, k)
	}

	sort.Sort(Headers(names))
	for _, k := range names {
		w.report("%s: %s", k, strings.Join(resp.Header[k], ","))
	}

	if bodyMsg != "" {
		w.report("%s", bodyMsg)
	}

	fmta := func(d time.Duration) string {
		return fmt.Sprintf("%dms", int(d/time.Millisecond))
	}

	fmtb := func(d time.Duration) string {
		return fmt.Sprintf("%dms", int(d/time.Millisecond))
	}

	w.report("DNS lookup: %s", fmta(t1.Sub(t0)))        // dns lookup
	w.report("TCP connection: %s", fmta(t2.Sub(t1)))    // tcp connection
	w.report("TLS handshake: %s", fmta(t3.Sub(t2)))     // tls handshake
	w.report("Server processing: %s", fmta(t4.Sub(t3))) // server processing
	w.report("Content transfer: %s", fmta(t5.Sub(t4)))  // content transfer

	w.report("\nTotal: %s", fmtb(t5.Sub(t0)))

	if r.FollowRedirects && isRedirect(resp) {
		loc, err := resp.Location()
		if err != nil {
			if err == http.ErrNoLocation {
				// 30x but no Location to follow, give up.
				return
			}
			makePanic("Unable to follow redirect: %v", err)
		}

		w.redirectsFollowed++
		if w.redirectsFollowed > r.MaxRedirects {
			makePanic("Maximum number of redirects (%d) followed", r.MaxRedirects)
		}

		r.URL = loc
		w.report("\n")
		r.visit(w)
	}
}

func (r *Request) cook() *http.Request {
	req, err := http.NewRequest(r.HTTPMethod,
		r.URL.String(),
		createBody(r.PostBody))

	if err != nil {
		makePanic("Unable to create request: %v", err)
	}

	for _, h := range r.HTTPHeaders {
		k, v := headerKeyValue(h)
		if strings.EqualFold(k, "host") {
			req.Host = v
			continue
		}
		req.Header.Add(k, v)
	}
	return req
}

func createBody(body string) io.Reader {
	return strings.NewReader(body)
}
