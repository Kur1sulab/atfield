package store

// canonical.go —— 与 Python json.dumps(sort_keys=True, separators=(",",":"),
// ensure_ascii=False) **逐字节一致**的规范化 JSON。
//
// 为什么非要逐字节一致：审计链的 hash 是对规范化字符串算的。两版共用过一个
// data_dir 之后，旧记录必须还能验——差一个 `.0` 或一个 `\u003c` 就是全链报错。
//
// 三个必须自己实现的差异点（Go 的 encoding/json 与 Python 不一致）：
//  1. 整数值的 float：Python repr(1700000000.0) == "1700000000.0"，Go 输出 "1700000000"。
//  2. HTML 转义：Go 把 < > & 改成 \u003c \u003e \u0026；Python 原样保留。
//  3. int 与 float 的区分：Go 的 json.Unmarshal 到 any 会把一切都变 float64，
//     于是 Python 写的 "n":3 会被读成 3.0、再算 hash 就对不上。读的时候用
//     json.Number 保住字面量（见 decodeRecord）。

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// canonicalJSON 把任意值写成 Python 口径的紧凑 JSON。
func canonicalJSON(v any) (string, error) {
	var sb strings.Builder
	if err := writeCanonical(&sb, reflect.ValueOf(v)); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func writeCanonical(sb *strings.Builder, rv reflect.Value) error {
	if !rv.IsValid() {
		sb.WriteString("null")
		return nil
	}
	// json.Number 走最前面：它代表「磁盘上原本的字面量」，
	// 必须原样吐回去，否则校验时会平白算出不同的 hash。
	if rv.Type() == reflect.TypeOf(json.Number("")) {
		sb.WriteString(string(rv.Interface().(json.Number)))
		return nil
	}

	switch rv.Kind() {
	case reflect.Interface, reflect.Pointer:
		if rv.IsNil() {
			sb.WriteString("null")
			return nil
		}
		return writeCanonical(sb, rv.Elem())

	case reflect.Bool:
		if rv.Bool() {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
		return nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		sb.WriteString(strconv.FormatInt(rv.Int(), 10))
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		sb.WriteString(strconv.FormatUint(rv.Uint(), 10))
		return nil

	case reflect.Float32:
		sb.WriteString(pyFloat(rv.Float(), 32))
		return nil

	case reflect.Float64:
		sb.WriteString(pyFloat(rv.Float(), 64))
		return nil

	case reflect.String:
		sb.WriteString(pyQuote(rv.String()))
		return nil

	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			sb.WriteString("null")
			return nil
		}
		sb.WriteByte('[')
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeCanonical(sb, rv.Index(i)); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
		return nil

	case reflect.Map:
		if rv.IsNil() {
			sb.WriteString("null")
			return nil
		}
		keys := rv.MapKeys()
		names := make([]string, 0, len(keys))
		byName := make(map[string]reflect.Value, len(keys))
		for _, k := range keys {
			name := fmt.Sprint(k.Interface())
			names = append(names, name)
			byName[name] = rv.MapIndex(k)
		}
		sort.Strings(names)
		sb.WriteByte('{')
		for i, name := range names {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(pyQuote(name))
			sb.WriteByte(':')
			if err := writeCanonical(sb, byName[name]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
		return nil

	case reflect.Struct:
		// 结构体按字段名排序输出（等价 sort_keys=True）。
		t := rv.Type()
		type kv struct {
			name string
			val  reflect.Value
		}
		items := make([]kv, 0, t.NumField())
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" { // 未导出字段
				continue
			}
			name := f.Name
			tag := f.Tag.Get("json")
			if tag != "" {
				parts := strings.Split(tag, ",")
				if parts[0] == "-" {
					continue
				}
				if parts[0] != "" {
					name = parts[0]
				}
			}
			items = append(items, kv{name: name, val: rv.Field(i)})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
		sb.WriteByte('{')
		for i, it := range items {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(pyQuote(it.name))
			sb.WriteByte(':')
			if err := writeCanonical(sb, it.val); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
		return nil
	}

	return fmt.Errorf("canonical: 不支持的类型 %s", rv.Type())
}

// pyFloat 复刻 Python repr(float)：
//
//	repr(3.0)          == "3.0"                 （整数值必须带 .0）
//	repr(1700000000.0) == "1700000000.0"
//	repr(1e15)         == "1000000000000000.0"
//	repr(1e16)         == "1e+16"               （decpt > 16 转科学计数）
//	repr(0.0001)       == "0.0001"
//	repr(1e-05)        == "1e-05"               （decpt <= -4 转科学计数）
//
// 规则来自 CPython float_repr → PyOS_double_to_string(mode='r')：
// 先取最短往返表示，再按小数点位置 decpt 决定定点还是科学计数。
func pyFloat(v float64, bits int) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		// JSON 没有 NaN/Inf，Python 会写成 NaN/Infinity（非标准）。
		// 审计链不该出现这种值；真出现了就按 Python 的写法吐出去。
		switch {
		case math.IsNaN(v):
			return "NaN"
		case v > 0:
			return "Infinity"
		default:
			return "-Infinity"
		}
	}
	if v == 0 {
		if math.Signbit(v) {
			return "-0.0"
		}
		return "0.0"
	}

	neg := v < 0
	abs := math.Abs(v)

	// 最短往返的十进制数字 + 十进制指数
	s := strconv.FormatFloat(abs, 'e', -1, bits)
	mant, expPart, ok := strings.Cut(s, "e")
	if !ok {
		return s
	}
	exp, err := strconv.Atoi(expPart)
	if err != nil {
		return s
	}
	digits := strings.Replace(mant, ".", "", 1)
	// 去掉尾随 0（'e' 格式已经是最短表示，这里只是保险）
	digits = strings.TrimRight(digits, "0")
	if digits == "" {
		digits = "0"
	}
	decpt := exp + 1 // 小数点前的位数

	var out string
	switch {
	case decpt > 16 || decpt <= -4:
		// 科学计数：d[.ddd]e±XX（指数至少两位）
		var m strings.Builder
		m.WriteByte(digits[0])
		if len(digits) > 1 {
			m.WriteByte('.')
			m.WriteString(digits[1:])
		}
		e := decpt - 1
		sign := "+"
		if e < 0 {
			sign = "-"
			e = -e
		}
		es := strconv.Itoa(e)
		if len(es) < 2 {
			es = "0" + es
		}
		out = m.String() + "e" + sign + es
	case decpt <= 0:
		// 0.000ddd
		out = "0." + strings.Repeat("0", -decpt) + digits
	default:
		if decpt >= len(digits) {
			out = digits + strings.Repeat("0", decpt-len(digits)) + ".0"
		} else {
			out = digits[:decpt] + "." + digits[decpt:]
		}
	}
	if neg {
		return "-" + out
	}
	return out
}

// pyQuote 复刻 Python json.dumps(ensure_ascii=False) 的字符串转义：
// 只转 " \ 与 < 0x20 的控制字符，其余（含 < > & 与全部非 ASCII）原样输出。
func pyQuote(s string) string {
	var sb strings.Builder
	sb.Grow(len(s) + 2)
	sb.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		switch c {
		case '"':
			sb.WriteString(`\"`)
			i++
			continue
		case '\\':
			sb.WriteString(`\\`)
			i++
			continue
		case '\n':
			sb.WriteString(`\n`)
			i++
			continue
		case '\r':
			sb.WriteString(`\r`)
			i++
			continue
		case '\t':
			sb.WriteString(`\t`)
			i++
			continue
		case '\b':
			sb.WriteString(`\b`)
			i++
			continue
		case '\f':
			sb.WriteString(`\f`)
			i++
			continue
		}
		if c < 0x20 {
			sb.WriteString(fmt.Sprintf(`\u%04x`, c))
			i++
			continue
		}
		if c < utf8.RuneSelf {
			sb.WriteByte(c)
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// 非法 UTF-8 字节：Python 会抛异常；这里用替换符兜住，
			// 审计链不该因为一条坏字符串整条写不进去。
			sb.WriteRune(utf8.RuneError)
			i++
			continue
		}
		sb.WriteString(s[i : i+size])
		i += size
	}
	sb.WriteByte('"')
	return sb.String()
}
