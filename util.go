package ysepay

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"github.com/tidwall/gjson"
	"golang.org/x/crypto/pkcs12"
)

var fail = func(err error) (gjson.Result, error) { return gjson.Result{}, err }

// ErrAccepting 网关受理中
var ErrAccepting = errors.New("SYS001 | 网关受理中")

const (
	CodeOK        = "SYS000" // 网关受理成功响应码
	CodeAccepting = "SYS001" // 网关受理中响应码
)

// X 类型别名
type X map[string]string

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
