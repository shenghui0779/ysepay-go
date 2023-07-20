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

// SetHTTPClient 设置 HTTP Client
func (c *YSEClient) SetHTTPClient(cli *http.Client) {
	c.client = NewHTTPClient(cli)
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
		return nil, fmt.Errorf("unexpected http status: %d", resp.StatusCode)
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
	np := NewNotifyParams(form)

	if err := np.Verify(c.pubKey); err != nil {
		return nil, err
	}

	var ret X

	if err := json.Unmarshal([]byte(np.BizJSON), &ret); err != nil {
		return nil, err
	}

	return ret, nil
}

// NewYSEClient 生成银盛支付Client
func NewYSEClient(mchNO, desKey string, prvKey *PrivateKey, pubKey *PublicKey) *YSEClient {
	return &YSEClient{
		host:   "https://eqt.ysepay.com",
		mchNO:  mchNO,
		desECB: NewDesECB([]byte(desKey), DES_PKCS5),
		prvKey: prvKey,
		pubKey: pubKey,
		client: NewDefaultHTTPClient(),
	}
}
