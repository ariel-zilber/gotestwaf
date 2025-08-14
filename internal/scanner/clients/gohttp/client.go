package gohttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/wallarm/gotestwaf/internal/config"
	"github.com/wallarm/gotestwaf/internal/helpers"
	"github.com/wallarm/gotestwaf/internal/payload"
	"github.com/wallarm/gotestwaf/internal/payload/placeholder"
	"github.com/wallarm/gotestwaf/internal/scanner/clients"
	"github.com/wallarm/gotestwaf/internal/scanner/types"
	"github.com/wallarm/gotestwaf/pkg/dnscache"
)

const (
	getCookiesRepeatAttempts = 3
)

var redirectFunc func(req *http.Request, via []*http.Request) error

var _ clients.HTTPClient = (*Client)(nil)

type Client struct {
	client     *http.Client
	headers    map[string]string
	hostHeader string

	followCookies bool
	renewSession  bool
	dumpRequests  bool

	dumpRequestsDir string
}

// dumpTraffic handles writing the request/response dump to a file or stdout.
func (c *Client) dumpTraffic(dump []byte, isRequest bool) {
	if c.dumpRequests {
		typeStr := "RESPONSE"
		if isRequest {
			typeStr = "REQUEST"
		}
		fmt.Printf("\n--- %s ---\n%s\n", typeStr, string(dump))
	}

	if c.dumpRequestsDir != "" {
		subDir := "responses"
		if isRequest {
			subDir = "requests"
		}
		
		dirPath := filepath.Join(c.dumpRequestsDir, subDir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			// Handle error if you can't create the subdirectory
			fmt.Printf("Error creating subdirectory %s: %v\n", subDir, err)
			return
		}

		hash := sha256.Sum256(dump)
		fileName := hex.EncodeToString(hash[:]) + ".black"
		filePath := filepath.Join(dirPath, fileName)
		_ = os.WriteFile(filePath, dump, 0644)
	}
}

func NewClient(cfg *config.Config, dnsResolver *dnscache.Resolver) (*Client, error) {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: !cfg.TLSVerify},
		IdleConnTimeout:     time.Duration(cfg.IdleConnTimeout) * time.Second,
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConns,
	}

	if dnsResolver != nil {
		tr.DialContext = dnscache.DialFunc(dnsResolver, nil)
	}

	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, errors.Wrap(err, "couldn't parse proxy URL")
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	redirectFunc = func(req *http.Request, via []*http.Request) error {
		if cfg.MaxRedirects == 0 {
			return http.ErrUseLastResponse
		}
		if len(via) > cfg.MaxRedirects {
			return errors.New("max redirect number exceeded")
		}
		return nil
	}

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: redirectFunc,
	}

	if cfg.FollowCookies && !cfg.RenewSession {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		client.Jar = jar
	}

	configuredHeaders := helpers.DeepCopyMap(cfg.HTTPHeaders)
	customHeader := strings.SplitN(cfg.AddHeader, ":", 2)
	if len(customHeader) > 1 {
		header := strings.TrimSpace(customHeader[0])
		value := strings.TrimSpace(customHeader[1])
		configuredHeaders[header] = value
	}

	if cfg.DumpRequestsDir != "" {
		if err := os.MkdirAll(cfg.DumpRequestsDir, 0755); err != nil {
			return nil, errors.Wrap(err, "failed to create dump requests directory")
		}
	}

	return &Client{
		client:          client,
		headers:         configuredHeaders,
		hostHeader:      configuredHeaders["Host"],
		followCookies:   cfg.FollowCookies,
		renewSession:    cfg.RenewSession,
		dumpRequests:    cfg.DumpRequests,
		dumpRequestsDir: cfg.DumpRequestsDir,
	}, nil
}

func (c *Client) SendPayload(
	ctx context.Context,
	targetURL string,
	payloadInfo *payload.PayloadInfo,
) (types.Response, error) {
	request, err := payloadInfo.GetRequest(targetURL, types.GoHTTPClient)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't prepare request")
	}

	r, ok := request.(*types.GoHTTPRequest)
	if !ok {
		return nil, errors.Errorf("bad request type: %T, expected %T", request, &types.GoHTTPRequest{})
	}

	req := r.Req.WithContext(ctx)

	isUAPlaceholder := payloadInfo.PlaceholderName == placeholder.DefaultUserAgent.GetName()

	for header, value := range c.headers {
		if strings.EqualFold(header, placeholder.UAHeader) && isUAPlaceholder {
			continue
		}
		if req.Header.Get(header) == "" {
			req.Header.Set(header, value)
		}
	}
	req.Host = c.hostHeader

	if payloadInfo.DebugHeaderValue != "" {
		req.Header.Set(clients.GTWDebugHeader, payloadInfo.DebugHeaderValue)
	}

	if c.followCookies && c.renewSession {
		cookies, err := c.getCookies(ctx, targetURL)
		if err != nil {
			return nil, errors.Wrap(err, "couldn't get cookies for malicious request")
		}

		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
	}

	if c.dumpRequests || c.dumpRequestsDir != "" {
		reqDump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			c.dumpTraffic(reqDump, true)
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "sending http request")
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading response body")
	}
	resp.Body.Close()

	// Replace the body so it can be read by DumpResponse
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	if c.dumpRequests || c.dumpRequestsDir != "" {
		respDump, err := httputil.DumpResponse(resp, true)
		if err == nil {
			c.dumpTraffic(respDump, false)
		}
	}
	
	// Reset the body again so it can be read by other parts of the program
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	statusCode := resp.StatusCode
	reasonIndex := strings.Index(resp.Status, " ")
	reason := resp.Status[reasonIndex+1:]

	if c.followCookies && !c.renewSession && c.client.Jar != nil {
		c.client.Jar.SetCookies(req.URL, resp.Cookies())
	}

	response := &types.ResponseMeta{
		StatusCode:   statusCode,
		StatusReason: reason,
		Headers:      resp.Header,
		Content:      bodyBytes,
	}

	return response, nil
}

func (c *Client) SendRequest(ctx context.Context, req types.Request) (types.Response, error) {
	r, ok := req.(*types.GoHTTPRequest)
	if !ok {
		return nil, errors.Errorf("bad request type: %T, expected %T", req, &types.GoHTTPRequest{})
	}

	r.Req = r.Req.WithContext(ctx)

	if c.followCookies && c.renewSession {
		cookies, err := c.getCookies(ctx, helpers.GetTargetURLStr(r.Req.URL))
		if err != nil {
			return nil, errors.Wrap(err, "couldn't get cookies for malicious request")
		}
		for _, cookie := range cookies {
			r.Req.AddCookie(cookie)
		}
	}

	for header, value := range c.headers {
		r.Req.Header.Set(header, value)
	}
	r.Req.Host = c.hostHeader

	if r.DebugHeaderValue != "" {
		r.Req.Header.Set(clients.GTWDebugHeader, r.DebugHeaderValue)
	}

	if c.dumpRequests || c.dumpRequestsDir != "" {
		reqDump, err := httputil.DumpRequestOut(r.Req, true)
		if err == nil {
			c.dumpTraffic(reqDump, true)
		}
	}

	resp, err := c.client.Do(r.Req)
	if err != nil {
		return nil, errors.Wrap(err, "sending http request")
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading response body")
	}
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	if c.dumpRequests || c.dumpRequestsDir != "" {
		respDump, err := httputil.DumpResponse(resp, true)
		if err == nil {
			c.dumpTraffic(respDump, false)
		}
	}

	statusCode := resp.StatusCode

	if c.followCookies && !c.renewSession && c.client.Jar != nil {
		c.client.Jar.SetCookies(r.Req.URL, resp.Cookies())
	}

	reasonIndex := strings.Index(resp.Status, " ")
	reason := resp.Status[reasonIndex+1:]

	response := &types.ResponseMeta{
		StatusCode:   statusCode,
		StatusReason: reason,
		Headers:      resp.Header,
		Content:      bodyBytes,
	}

	return response, nil
}

func (c *Client) getCookies(ctx context.Context, targetURL string) ([]*http.Cookie, error) {
	tr, ok := c.client.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("couldn't copy transport settings of the main HTTP to get cookies")
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't create cookie jar for session renewal client")
	}

	sessionClient := &http.Client{
		Transport: &http.Transport{
			DialContext:         tr.DialContext,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: tr.TLSClientConfig.InsecureSkipVerify},
			IdleConnTimeout:     tr.IdleConnTimeout,
			MaxIdleConns:        tr.MaxIdleConns,
			MaxIdleConnsPerHost: tr.MaxIdleConnsPerHost,
			Proxy:               tr.Proxy,
		},
		CheckRedirect: redirectFunc,
		Jar:           jar,
	}

	var returnErr error

	for i := 0; i < getCookiesRepeatAttempts; i++ {
		cookiesReq, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			returnErr = err
			continue
		}

		for header, value := range c.headers {
			cookiesReq.Header.Set(header, value)
		}
		cookiesReq.Host = c.hostHeader

		cookieResp, err := sessionClient.Do(cookiesReq)
		if err != nil {
			returnErr = err
			continue
		}
		cookieResp.Body.Close()

		return sessionClient.Jar.Cookies(cookiesReq.URL), nil
	}

	return nil, returnErr
}