package ysepay

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

type httpSetting struct {
	header http.Header
	cookie []*http.Cookie
	close  bool
}

// HTTPOption HTTP请求选项
type HTTPOption func(s *httpSetting)

// WithHTTPHeader 设置HTTP请求头
func WithHTTPHeader(key string, vals ...string) HTTPOption {
	return func(s *httpSetting) {
		if len(vals) == 1 {
			s.header.Set(key, vals[0])

			return
		}

		for _, v := range vals {
			s.header.Add(key, v)
		}
	}
}

// WithHTTPCookies 设置HTTP请求Cookie
func WithHTTPCookies(cookies ...*http.Cookie) HTTPOption {
	return func(s *httpSetting) {
		s.cookie = cookies
	}
}

// WithHTTPClose 请求结束后关闭请求
func WithHTTPClose() HTTPOption {
	return func(s *httpSetting) {
		s.close = true
	}
}

// HTTPClient HTTP客户端
type HTTPClient interface {
	// Do 发送HTTP请求
	// 注意：应该使用Context设置请求超时时间
	Do(ctx context.Context, method, reqURL string, body []byte, options ...HTTPOption) (*http.Response, error)
}

type httpCli struct {
	client *http.Client
}

func (c *httpCli) Do(ctx context.Context, method, reqURL string, body []byte, options ...HTTPOption) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	setting := new(httpSetting)

	if len(options) != 0 {
		setting.header = http.Header{}

		for _, f := range options {
			f(setting)
		}
	}

	// header
	if len(setting.header) != 0 {
		req.Header = setting.header
	}

	// cookie
	if len(setting.cookie) != 0 {
		for _, v := range setting.cookie {
			req.AddCookie(v)
		}
	}

	if setting.close {
		req.Close = true
	}

	resp, err := c.client.Do(req)
	if err != nil {
		// If the context has been canceled, the context's error is probably more useful.
		select {
		case <-ctx.Done():
			err = ctx.Err()
		default:
		}

		return nil, err
	}

	return resp, nil
}

// NewHTTPClient 通过官方 `http.Client` 生成一个HTTP客户端
func NewHTTPClient(cli *http.Client) HTTPClient {
	return &httpCli{
		client: cli,
	}
}

// NewDefaultHTTPClient 生成一个默认的HTTP客户端
func NewDefaultHTTPClient() HTTPClient {
	return &httpCli{
		client: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 60 * time.Second,
				}).DialContext,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				MaxIdleConns:          0,
				MaxIdleConnsPerHost:   1000,
				MaxConnsPerHost:       1000,
				IdleConnTimeout:       60 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: time.Second,
			},
		},
	}
}
