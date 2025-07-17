package mcp

import (
	"encoding/hex"
	"strconv"
	"strings"
)

type HexUint64 uint64

func (h *HexUint64) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)   // 去除 JSON 字符串的引号
	s = strings.TrimPrefix(s, "0x")        // 去掉 "0x" 前缀
	v, err := strconv.ParseUint(s, 16, 64) // 按十六进制解析
	*h = HexUint64(v)
	return err
}
func (h HexUint64) MarshalJSON() ([]byte, error) {
	return []byte(`"` + "0x" + strconv.FormatUint(uint64(h), 16) + `"`), nil
}

type HexInt uint

func (h *HexInt) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)  // 去除 JSON 字符串的引号
	s = strings.TrimPrefix(s, "0x")       // 去掉 "0x" 前缀
	v, err := strconv.ParseInt(s, 16, 64) // 按十六进制解析
	*h = HexInt(v)
	return err
}

type HexBytes []byte

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	s = strings.TrimPrefix(s, "0x")
	decoded, err := hex.DecodeString(s)
	*h = decoded
	return err
}

type HexString string

func (h *HexString) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	s = strings.TrimPrefix(s, "0x")
	decoded, err := hex.DecodeString(s)
	*h = HexString(decoded)
	return err
}
