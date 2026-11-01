package tcp

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

type Fingerprint struct {
	TCP string
	TTL string
	JA4 string
}

type FingerprintConn interface {
	Fingerprint() *Fingerprint
}

func (f *Fingerprint) SetSYN(syn []byte) {
	if len(syn) == 0 {
		return
	}

	var ttl uint8
	var header []byte
	switch syn[0] >> 4 {
	case 4:
		ihl := int(syn[0]&0x0f) * 4
		if ihl < 20 || len(syn) < ihl || syn[9] != 6 {
			return
		}
		ttl = syn[8]
		header = syn[ihl:]
	case 6:
		if len(syn) < 40 || syn[6] != 6 {
			return
		}
		ttl = syn[7]
		header = syn[40:]
	default:
		return
	}

	if len(header) < 20 {
		return
	}
	dataOffset := int(header[12]>>4) * 4
	if dataOffset < 20 || len(header) < dataOffset {
		return
	}

	window := binary.BigEndian.Uint16(header[14:16])
	options := header[20:dataOffset]

	var kinds []string
	var mss uint16
	var wscale uint8
	for i := 0; i < len(options); {
		kind := options[i]
		kinds = append(kinds, strconv.Itoa(int(kind)))
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(options) {
			break
		}
		length := int(options[i+1])
		if length < 2 || i+length > len(options) {
			break
		}
		switch {
		case kind == 2 && length == 4:
			mss = binary.BigEndian.Uint16(options[i+2 : i+4])
		case kind == 3 && length == 3:
			wscale = options[i+2]
		}
		i += length
	}

	f.TTL = strconv.Itoa(int(ttl))
	f.TCP = fmt.Sprintf("%d_%s_%d_%d", window, strings.Join(kinds, "-"), mss, wscale)
}

func (f *Fingerprint) SetClientHello(hello *tls.ClientHelloInfo) {
	ciphers := withoutGREASE(hello.CipherSuites)
	extensions := withoutGREASE(hello.Extensions)

	sni := "i"
	if slices.Contains(extensions, 0x0000) {
		sni = "d"
	}

	prefix := fmt.Sprintf("t%s%s%02d%02d%s", ja4Version(hello.SupportedVersions), sni, min(len(ciphers), 99), min(len(extensions), 99), ja4ALPN(hello.SupportedProtos))

	slices.Sort(ciphers)

	extensions = slices.DeleteFunc(extensions, func(e uint16) bool { return e == 0x0000 || e == 0x0010 })
	slices.Sort(extensions)

	exts := hexList(extensions)
	if signatures := withoutGREASE(hello.SignatureSchemes); len(signatures) > 0 {
		exts += "_" + hexList(signatures)
	}

	f.JA4 = prefix + "_" + ja4Hash(hexList(ciphers)) + "_" + ja4Hash(exts)
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func withoutGREASE[T ~uint16](values []T) []uint16 {
	result := make([]uint16, 0, len(values))
	for _, v := range values {
		if !isGREASE(uint16(v)) {
			result = append(result, uint16(v))
		}
	}
	return result
}

func ja4Version(versions []uint16) string {
	var highest uint16
	for _, v := range versions {
		if !isGREASE(v) {
			highest = max(highest, v)
		}
	}

	switch highest {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return "00"
	}
}

func ja4ALPN(protos []string) string {
	if len(protos) == 0 || protos[0] == "" {
		return "00"
	}

	proto := protos[0]
	first, last := proto[0], proto[len(proto)-1]
	if isAlphanumeric(first) && isAlphanumeric(last) {
		return string([]byte{first, last})
	}

	encoded := hex.EncodeToString([]byte(proto))
	return string([]byte{encoded[0], encoded[len(encoded)-1]})
}

func isAlphanumeric(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func hexList(values []uint16) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func ja4Hash(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}
