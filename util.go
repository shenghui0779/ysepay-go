package ysepay

import (
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/pkcs12"
)

// ErrAccepting 网关受理中
var ErrAccepting = errors.New("SYS001 | 网关受理中")

const (
	CodeOK        = "SYS000" // 网关受理成功响应码
	CodeAccepting = "SYS001" // 网关受理中响应码
)

// X 类型别名
type X map[string]string

// CommonReq 公关请求参数
type CommonReq struct {
	ReqID     string `json:"requestId"`
	MchNO     string `json:"srcMerchantNo"`
	Version   string `json:"version"`
	Charset   string `json:"charset"`
	ServiceNO string `json:"serviceNo"`
	SignType  string `json:"signType"`
	Sign      string `json:"sign"`
	BizJSON   string `json:"bizReqJson"`
}

// DoSign 生成签名
func (req *CommonReq) DoSign(key *PrivateKey) error {
	if key == nil {
		return errors.New("private key is nil (forgotten configure?)")
	}

	var builder strings.Builder

	if len(req.BizJSON) != 0 {
		builder.WriteString("bizReqJson=")
		builder.WriteString(req.BizJSON)
		builder.WriteString("&")
	}

	builder.WriteString("charset=")
	builder.WriteString(req.Charset)
	builder.WriteString("&")

	builder.WriteString("requestId=")
	builder.WriteString(req.ReqID)
	builder.WriteString("&")

	builder.WriteString("serviceNo=")
	builder.WriteString(req.ServiceNO)
	builder.WriteString("&")

	builder.WriteString("signType=")
	builder.WriteString(req.SignType)
	builder.WriteString("&")

	builder.WriteString("srcMerchantNo=")
	builder.WriteString(req.MchNO)
	builder.WriteString("&")

	builder.WriteString("version=")
	builder.WriteString(req.Version)

	sign, err := key.Sign(crypto.SHA1, []byte(builder.String()))

	if err != nil {
		return err
	}

	req.Sign = base64.StdEncoding.EncodeToString(sign)

	return nil
}

// FormURLEncode 生成Form表单参数
func (req *CommonReq) FormURLEncode() string {
	form := url.Values{}

	form.Set("requestId", req.ReqID)
	form.Set("srcMerchantNo", req.MchNO)
	form.Set("version", req.Version)
	form.Set("serviceNo", req.ServiceNO)
	form.Set("signType", "RSA")
	form.Set("sign", req.Sign)

	if len(req.BizJSON) != 0 {
		form.Set("bizReqJson", req.BizJSON)
	}

	return form.Encode()
}

// NewCommonReq 返回公共请求参数
func NewCommonReq(mchNO, serviceNO string, bizData X) (*CommonReq, error) {
	bizJSON := ""

	if len(bizData) != 0 {
		bizByte, err := json.Marshal(bizData)

		if err != nil {
			return nil, err
		}

		bizJSON = string(bizByte)
	}

	return &CommonReq{
		ReqID:     uuid.NewString(),
		MchNO:     mchNO,
		Version:   "v2.0.0",
		Charset:   "UTF-8",
		ServiceNO: serviceNO,
		SignType:  "RSA",
		BizJSON:   bizJSON,
	}, nil
}

// CommonResp 公关返回参数
type CommonResp struct {
	ReqID   string `json:"requestId"`
	Code    string `json:"code"`
	Msg     string `json:"msg"`
	Sign    string `json:"sign"`
	BizJSON string `json:"bizResponseJson"`
}

// Verify 签名验证
func (resp *CommonResp) Verify(reqID string, key *PublicKey) error {
	if key == nil {
		return errors.New("public key is nil (forgotten configure?)")
	}

	sign, err := base64.StdEncoding.DecodeString(resp.Sign)

	if err != nil {
		return err
	}

	var builder strings.Builder

	if len(resp.BizJSON) != 0 {
		builder.WriteString("bizResponseJson=")
		builder.WriteString(resp.BizJSON)
		builder.WriteString("&")
	}

	builder.WriteString("code=")
	builder.WriteString(resp.Code)
	builder.WriteString("&")

	builder.WriteString("msg=")
	builder.WriteString(resp.Msg)
	builder.WriteString("&")

	builder.WriteString("requestId=")
	builder.WriteString(resp.ReqID)

	if err = key.Verify(crypto.SHA1, []byte(builder.String()), sign); err != nil {
		return err
	}

	if resp.ReqID != reqID {
		return fmt.Errorf("requestID mismatch, request: %s, response: %s", reqID, resp.ReqID)
	}

	return nil
}

// NotifyForm 异步回调通知表单数据
type NotifyForm struct {
	ReqID     string `json:"requestId"`
	Version   string `json:"version"`
	Charset   string `json:"charset"`
	ServiceNO string `json:"serviceNo"`
	SignType  string `json:"signType"`
	Sign      string `json:"sign"`
	BizJSON   string `json:"bizResponseJson"`
}

// Verify 签名验证
func (nf *NotifyForm) Verify(key *PublicKey) error {
	if key == nil {
		return errors.New("public key is nil (forgotten configure?)")
	}

	sign, err := base64.StdEncoding.DecodeString(nf.Sign)

	if err != nil {
		return err
	}

	var builder strings.Builder

	if len(nf.BizJSON) != 0 {
		builder.WriteString("bizReqJson=")
		builder.WriteString(nf.BizJSON)
		builder.WriteString("&")
	}

	builder.WriteString("charset=")
	builder.WriteString(nf.Charset)
	builder.WriteString("&")

	builder.WriteString("requestId=")
	builder.WriteString(nf.ReqID)
	builder.WriteString("&")

	builder.WriteString("serviceNo=")
	builder.WriteString(nf.ServiceNO)
	builder.WriteString("&")

	builder.WriteString("signType=")
	builder.WriteString(nf.SignType)
	builder.WriteString("&")

	builder.WriteString("version=")
	builder.WriteString(nf.Version)

	return key.Verify(crypto.SHA1, []byte(builder.String()), sign)
}

// NewNotifyForm 生成异步回调参数
func NewNotifyForm(form url.Values) *NotifyForm {
	return &NotifyForm{
		ReqID:     form.Get("requestId"),
		Version:   form.Get("version"),
		Charset:   form.Get("charset"),
		ServiceNO: form.Get("serviceNo"),
		SignType:  form.Get("signType"),
		Sign:      form.Get("sign"),
		BizJSON:   form.Get("bizResponseJson"),
	}
}

// LoadCertFromPfxFile 通过pfx(p12)证书文件生成TLS证书
// 注意：证书需采用「TripleDES-SHA1」加密方式
func LoadCertFromPfxFile(filename, password string) (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }

	certPath, err := filepath.Abs(filepath.Clean(filename))

	if err != nil {
		return fail(err)
	}

	pfxdata, err := os.ReadFile(certPath)

	if err != nil {
		return fail(err)
	}

	blocks, err := pkcs12.ToPEM(pfxdata, password)

	if err != nil {
		return fail(err)
	}

	pemData := make([]byte, 0)

	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return tls.X509KeyPair(pemData, pemData)
}
