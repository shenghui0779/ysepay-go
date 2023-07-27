package ysepay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// YSEClient 银盛支付Client
type YSEClient struct {
	host   string
	mchNO  string
	desECB *DesECB
	prvKey *PrivateKey
	pubKey *PublicKey
	client HTTPClient
}

// SetHTTPClient 设置自定义Client
func (c *YSEClient) SetHTTPClient(cli *http.Client) {
	c.client = NewHTTPClient(cli)
}

// SetPrivateKeyFromPemBlock 通过PEM字节设置RSA私钥
func (c *YSEClient) SetPrivateKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) (err error) {
	c.prvKey, err = NewPrivateKeyFromPemBlock(mode, pemBlock)

	return
}

// SetPrivateKeyFromPemFile 通过PEM文件设置RSA私钥
func (c *YSEClient) SetPrivateKeyFromPemFile(mode RSAPaddingMode, pemFile string) (err error) {
	c.prvKey, err = NewPrivateKeyFromPemFile(mode, pemFile)

	return
}

// SetPrivateKeyFromPfxFile 通过pfx(p12)证书设置RSA私钥
// 注意：证书需采用「TripleDES-SHA1」加密方式
func (c *YSEClient) SetPrivateKeyFromPfxFile(pfxFile, password string) (err error) {
	c.prvKey, err = NewPrivateKeyFromPfxFile(pfxFile, password)

	return
}

// NewPublicKeyFromPemBlock 通过PEM字节设置RSA公钥
func (c *YSEClient) SetPublicKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) (err error) {
	c.pubKey, err = NewPublicKeyFromPemBlock(mode, pemBlock)

	return
}

// NewPublicKeyFromPemFile 通过PEM文件设置RSA公钥
func (c *YSEClient) SetPublicKeyFromPemFile(mode RSAPaddingMode, pemFile string) (err error) {
	c.pubKey, err = NewPublicKeyFromPemFile(mode, pemFile)

	return
}

// NewPublicKeyFromDerBlock 通过DER字节设置RSA公钥
// 注意PEM格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// DER转换命令: openssl x509 -inform der -in cert.cer -out cert.pem
func (c *YSEClient) SetPublicKeyFromDerBlock(pemBlock []byte) (err error) {
	c.pubKey, err = NewPublicKeyFromDerBlock(pemBlock)

	return
}

// NewPublicKeyFromDerFile 通过DER证书设置RSA公钥
// 注意PEM格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// DER转换命令: openssl x509 -inform der -in cert.cer -out cert.pem
func (c *YSEClient) SetPublicKeyFromDerFile(pemFile string) (err error) {
	c.pubKey, err = NewPublicKeyFromDerFile(pemFile)

	return
}

// URL 生成请求URL
func (c *YSEClient) URL(api string) string {
	var builder strings.Builder

	builder.WriteString(c.host)
	builder.WriteString("/api/")
	builder.WriteString(api)

	return builder.String()
}

// Encrypt 敏感数据DES加密
func (c *YSEClient) Encrypt(plain string) (string, error) {
	b, err := c.desECB.Encrypt([]byte(plain))

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

// Decrypt 敏感数据DES解密
func (c *YSEClient) Decrypt(cipher string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(cipher)

	if err != nil {
		return "", err
	}

	plain, err := c.desECB.Decrypt(b)

	if err != nil {
		return "", err
	}

	return string(plain), nil
}

// PostForm 发送POST表单请求
func (c *YSEClient) PostForm(ctx context.Context, api, serviceNO string, bizData X, options ...HTTPOption) (X, error) {
	commReq, err := NewCommonReq(c.mchNO, serviceNO, bizData)

	if err != nil {
		return nil, err
	}

	if err := commReq.DoSign(c.prvKey); err != nil {
		return nil, err
	}

	options = append(options, WithHTTPHeader("Content-Type", "application/x-www-form-urlencoded"))

	resp, err := c.client.Do(ctx, http.MethodPost, c.URL(api), []byte(commReq.FormURLEncode()), options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	commResp := new(CommonResp)

	if err = json.Unmarshal(b, commResp); err != nil {
		return nil, err
	}

	if err = commResp.Verify(commReq.ReqID, c.pubKey); err != nil {
		return nil, err
	}

	if commResp.Code != CodeOK {
		if commResp.Code == CodeAccepting {
			return nil, ErrAccepting
		}

		return nil, fmt.Errorf("%s | %s", commResp.Code, commResp.Msg)
	}

	var ret X

	if err = json.Unmarshal([]byte(commResp.BizJSON), &ret); err != nil {
		return nil, err
	}

	return ret, nil
}

// ParseNotify 解析异步回调通知，返回BizJSON数据
func (c *YSEClient) ParseNotify(form url.Values) (X, error) {
	nf := NewNotifyForm(form)

	if err := nf.Verify(c.pubKey); err != nil {
		return nil, err
	}

	var ret X

	if err := json.Unmarshal([]byte(nf.BizJSON), &ret); err != nil {
		return nil, err
	}

	return ret, nil
}

// NewYSEClient 生成银盛支付Client
func NewYSEClient(mchNO, desKey string) *YSEClient {
	return &YSEClient{
		host:   "https://eqt.ysepay.com",
		mchNO:  mchNO,
		desECB: NewDesECB([]byte(desKey), DES_PKCS5),
		client: NewDefaultHTTPClient(),
	}
}
