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
	ecb     *DesECB
	prvKey  *PrivateKey
	pubKey  *PublicKey
	httpCli HTTPClient
	logger  func(ctx context.Context, data map[string]string)
}

// SetHTTPClient 设置自定义Client
func (c *Client) SetHTTPClient(cli *http.Client) {
	c.httpCli = NewHTTPClient(cli)
}

// SetPrivateKeyFromPemBlock 通过PEM字节设置RSA私钥
func (c *Client) SetPrivateKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) error {
	key, err := NewPrivateKeyFromPemBlock(mode, pemBlock)

	if err != nil {
		return err
	}

	c.prvKey = key

	return nil
}

// SetPrivateKeyFromPemFile 通过PEM文件设置RSA私钥
func (c *Client) SetPrivateKeyFromPemFile(mode RSAPaddingMode, pemFile string) error {
	key, err := NewPrivateKeyFromPemFile(mode, pemFile)

	if err != nil {
		return err
	}

	c.prvKey = key

	return nil
}

// SetPrivateKeyFromPfxFile 通过pfx(p12)证书设置RSA私钥
// 注意：证书需采用「TripleDES-SHA1」加密方式
func (c *Client) SetPrivateKeyFromPfxFile(pfxFile, password string) error {
	key, err := NewPrivateKeyFromPfxFile(pfxFile, password)

	if err != nil {
		return err
	}

	c.prvKey = key

	return nil
}

// NewPublicKeyFromPemBlock 通过PEM字节设置RSA公钥
func (c *Client) SetPublicKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) error {
	key, err := NewPublicKeyFromPemBlock(mode, pemBlock)

	if err != nil {
		return err
	}

	c.pubKey = key

	return nil
}

// NewPublicKeyFromPemFile 通过PEM文件设置RSA公钥
func (c *Client) SetPublicKeyFromPemFile(mode RSAPaddingMode, pemFile string) error {
	key, err := NewPublicKeyFromPemFile(mode, pemFile)

	if err != nil {
		return err
	}

	c.pubKey = key

	return nil
}

// NewPublicKeyFromDerBlock 通过DER字节设置RSA公钥
// 注意PEM格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// DER转换命令: openssl x509 -inform der -in cert.cer -out cert.pem
func (c *Client) SetPublicKeyFromDerBlock(pemBlock []byte) error {
	key, err := NewPublicKeyFromDerBlock(pemBlock)

	if err != nil {
		return err
	}

	c.pubKey = key

	return nil
}

// NewPublicKeyFromDerFile 通过DER证书设置RSA公钥
// 注意PEM格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// DER转换命令: openssl x509 -inform der -in cert.cer -out cert.pem
func (c *Client) SetPublicKeyFromDerFile(pemFile string) error {
	key, err := NewPublicKeyFromDerFile(pemFile)

	if err != nil {
		return err
	}

	c.pubKey = key

	return nil
}

// WithLogger 设置日志记录
func (c *Client) WithLogger(f func(ctx context.Context, data map[string]string)) {
	c.logger = f
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
	b, err := c.ecb.Encrypt([]byte(plain))

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

// MustEncrypt 敏感数据DES加密；若发生错误，则返回错误信息
func (c *Client) MustEncrypt(plain string) string {
	b, err := c.ecb.Encrypt([]byte(plain))

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

	plain, err := c.ecb.Decrypt(b)

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

// NewClient 生成银盛支付客户端
func NewClient(mchNO, desKey string) *Client {
	return &Client{
		host:    "https://eqt.ysepay.com",
		mchNO:   mchNO,
		ecb:     NewDesECB([]byte(desKey), DES_PKCS5),
		httpCli: NewDefaultHTTPClient(),
	}
}
