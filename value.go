package ysepay

import (
	"net/url"
	"sort"
	"strings"
)

// V 用于处理 k-v 需要格式化的场景，如：签名
type V map[string]string

// Set 设置 k-v
func (v V) Set(key, value string) {
	v[key] = value
}

// Get 获取值
func (v V) Get(key string) string {
	return v[key]
}

// Del 删除Key
func (v V) Del(key string) {
	delete(v, key)
}

// Has 判断Key是否存在
func (v V) Has(key string) bool {
	_, ok := v[key]

	return ok
}

// Encode 通过自定义的符号和分隔符按照key的ASCII码升序格式化为字符串。
// 例如：("=", "&") ---> bar=baz&foo=quux；
// 例如：(":", "#") ---> bar:baz#foo:quux；
func (v V) Encode(sym, sep string, options ...VEncOption) string {
	if len(v) == 0 {
		return ""
	}

	setting := &vencSetting{
		ignoreKeys: make(map[string]struct{}),
	}

	for _, f := range options {
		f(setting)
	}

	keys := make([]string, 0, len(v))
	for k := range v {
		if _, ok := setting.ignoreKeys[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var buf strings.Builder

	for _, k := range keys {
		val := v[k]

		if len(val) == 0 && setting.emptyMode == EmptyEncIgnore {
			continue
		}

		if buf.Len() > 0 {
			buf.WriteString(sep)
		}

		if setting.escape {
			buf.WriteString(url.QueryEscape(k))
		} else {
			buf.WriteString(k)
		}

		if len(val) != 0 {
			buf.WriteString(sym)

			if setting.escape {
				buf.WriteString(url.QueryEscape(val))
			} else {
				buf.WriteString(val)
			}

			continue
		}

		// 保留符号
		if setting.emptyMode != EmptyEncOnlyKey {
			buf.WriteString(sym)
		}
	}

	return buf.String()
}

// VEmptyEncMode 值为空时的Encode模式
type VEmptyEncMode int

const (
	EmptyEncDefault VEmptyEncMode = iota // 默认：bar=baz&foo=
	EmptyEncIgnore                       // 忽略：bar=baz
	EmptyEncOnlyKey                      // 仅保留Key：bar=baz&foo
)

type vencSetting struct {
	escape     bool
	emptyMode  VEmptyEncMode
	ignoreKeys map[string]struct{}
}

// VEncOption V Encode 选项
type VEncOption func(s *vencSetting)

// WithEmptyEncodeMode 设置值为空时的Encode模式
func WithEmptyEncMode(mode VEmptyEncMode) VEncOption {
	return func(s *vencSetting) {
		s.emptyMode = mode
	}
}

// WithKVEscape 设置K-V是否需要QueryEscape
func WithKVEscape() VEncOption {
	return func(s *vencSetting) {
		s.escape = true
	}
}

// WithIgnoreKeys 设置Encode时忽略的key
func WithIgnoreKeys(keys ...string) VEncOption {
	return func(s *vencSetting) {
		for _, k := range keys {
			s.ignoreKeys[k] = struct{}{}
		}
	}
}
