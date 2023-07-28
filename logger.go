package ysepay

import "context"

// ReqLog 请求日志
type ReqLog struct {
	url  string
	body string
	resp string
}

// SetURL 设置请求URL
func (l *ReqLog) SetURL(v string) {
	l.url = v
}

// SetBody 设置请求Body
func (l *ReqLog) SetBody(v string) {
	l.body = v
}

// SetResp 设置返回报文
func (l *ReqLog) SetResp(v string) {
	l.resp = v
}

// Do 日志记录
func (l *ReqLog) Do(ctx context.Context, log func(ctx context.Context, url, body, resp string)) {
	if log == nil {
		return
	}

	log(ctx, l.url, l.body, l.resp)
}
