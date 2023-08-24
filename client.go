package ysepay

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

// Client 银盛支付客户端
type Client struct {
	host    string
	mchNO   string
	desKey  string
	prvKey  *PrivateKey
	pubKey  *PublicKey
	httpCli HTTPClient
	logger  func(ctx context.Context, data map[string]string)
}

// MchNO 返回商户号
func (c *Client) MchNO() string {
	return c.mchNO
}

// URL 生成请求URL
func (c *Client) URL(api string) string {
	var builder strings.Builder

	builder.WriteString(c.host)
	builder.WriteString("/api/")
	builder.WriteString(api)

	return builder.String()
}

// Encrypt 敏感数据DES加密
func (c *Client) Encrypt(plain string) (string, error) {
	ecb := NewDesECB([]byte(c.desKey), DES_PKCS5)

	b, err := ecb.Encrypt([]byte(plain))

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

// MustEncrypt 敏感数据DES加密；若发生错误，则返回错误信息
func (c *Client) MustEncrypt(plain string) string {
	ecb := NewDesECB([]byte(c.desKey), DES_PKCS5)

	b, err := ecb.Encrypt([]byte(plain))

	if err != nil {
		return err.Error()
	}

	return base64.StdEncoding.EncodeToString(b)
}

// Decrypt 敏感数据DES解密
func (c *Client) Decrypt(cipher string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(cipher)

	if err != nil {
		return "", err
	}

	ecb := NewDesECB([]byte(c.desKey), DES_PKCS5)

	plain, err := ecb.Decrypt(b)

	if err != nil {
		return "", err
	}

	return string(plain), nil
}

// PostForm 发送POST表单请求
func (c *Client) PostForm(ctx context.Context, api, serviceNO string, bizData V) (gjson.Result, error) {
	reqURL := c.URL(api)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	reqID := uuid.NewString()

	form, err := c.reqForm(reqID, serviceNO, bizData)

	if err != nil {
		return fail(err)
	}

	log.SetReqBody(form)

	resp, err := c.httpCli.Do(ctx, http.MethodPost, reqURL, []byte(form), WithHTTPHeader("Content-Type", "application/x-www-form-urlencoded"))

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	log.SetRespBody(string(b))

	ret, err := c.verifyResp(gjson.ParseBytes(b))

	if err != nil {
		return fail(err)
	}

	return ret, nil
}

// reqForm 生成请求表单
func (c *Client) reqForm(reqID, serviceNO string, bizData V) (string, error) {
	if c.prvKey == nil {
		return "", errors.New("private key is nil (forgotten configure?)")
	}

	v := V{}

	v.Set("requestId", reqID)
	v.Set("srcMerchantNo", c.mchNO)
	v.Set("version", "v2.0.0")
	v.Set("charset", "UTF-8")
	v.Set("serviceNo", serviceNO)
	v.Set("signType", "RSA")

	if len(bizData) != 0 {
		bizByte, err := json.Marshal(bizData)

		if err != nil {
			return "", err
		}

		v.Set("bizReqJson", string(bizByte))
	}

	sign, err := c.prvKey.Sign(crypto.SHA1, []byte(v.Encode("=", "&", WithIgnoreKeys("sign"), WithEmptyEncMode(EmptyEncIgnore))))

	if err != nil {
		return "", err
	}

	v.Set("sign", base64.StdEncoding.EncodeToString(sign))

	return v.Encode("=", "&", WithEmptyEncMode(EmptyEncIgnore), WithKVEscape()), nil
}

func (c *Client) verifyResp(ret gjson.Result) (gjson.Result, error) {
	if c.pubKey == nil {
		return fail(errors.New("public key is nil (forgotten configure?)"))
	}

	sign, err := base64.StdEncoding.DecodeString(ret.Get("sign").String())

	if err != nil {
		return fail(err)
	}

	v := V{}

	v.Set("requestId", ret.Get("requestId").String())
	v.Set("code", ret.Get("code").String())
	v.Set("msg", ret.Get("msg").String())
	v.Set("bizResponseJson", ret.Get("bizResponseJson").String())

	err = c.pubKey.Verify(crypto.SHA1, []byte(v.Encode("=", "&", WithEmptyEncMode(EmptyEncIgnore))), sign)

	if err != nil {
		return fail(err)
	}

	if code := ret.Get("code").String(); code != SysOK {
		if code == SysAccepting {
			return fail(ErrSysAccepting)
		}

		return fail(fmt.Errorf("%s | %s", code, ret.Get("msg").String()))
	}

	return ret.Get("bizResponseJson"), nil
}

// VerifyNotify 解析并验证异步回调通知，返回BizJSON数据
func (c *Client) VerifyNotify(form url.Values) (gjson.Result, error) {
	if c.pubKey == nil {
		return fail(errors.New("public key is nil (forgotten configure?)"))
	}

	sign, err := base64.StdEncoding.DecodeString(form.Get("sign"))

	if err != nil {
		return fail(err)
	}

	v := V{}

	v.Set("requestId", form.Get("requestId"))
	v.Set("version", form.Get("version"))
	v.Set("charset", form.Get("charset"))
	v.Set("serviceNo", form.Get("serviceNo"))
	v.Set("signType", form.Get("signType"))
	v.Set("bizResponseJson", form.Get("bizResponseJson"))

	err = c.pubKey.Verify(crypto.SHA1, []byte(v.Encode("=", "&", WithEmptyEncMode(EmptyEncIgnore))), sign)

	if err != nil {
		return fail(err)
	}

	return gjson.Parse(form.Get("bizResponseJson")), nil
}

// Option 自定义设置项
type Option func(c *Client)

// WithClient 设置自定义 HTTP Client
func WithClient(cli *http.Client) Option {
	return func(c *Client) {
		c.httpCli = NewHTTPClient(cli)
	}
}

// WithPrivateKey 设置商户RSA私钥
func WithPrivateKey(key *PrivateKey) Option {
	return func(c *Client) {
		c.prvKey = key
	}
}

// WithPublicKey 设置平台RSA公钥
func WithPublicKey(key *PublicKey) Option {
	return func(c *Client) {
		c.pubKey = key
	}
}

// WithLogger 设置日志记录
func WithLogger(f func(ctx context.Context, data map[string]string)) Option {
	return func(c *Client) {
		c.logger = f
	}
}

// NewClient 生成银盛支付客户端
func NewClient(mchNO, desKey string, options ...Option) *Client {
	c := &Client{
		host:    "https://eqt.ysepay.com",
		mchNO:   mchNO,
		desKey:  desKey,
		httpCli: NewDefaultHTTPClient(),
	}

	for _, f := range options {
		f(c)
	}

	return c
}
