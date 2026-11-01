package tcp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprint_SetSYN(t *testing.T) {
	syn := []byte{
		0x45, 0x00, 0x00, 0x3c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
		0xd4, 0x31, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0xa0, 0x02, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
	}

	var fingerprint Fingerprint
	fingerprint.SetSYN(syn)

	assert.Equal(t, "1460_64240_7_2-4-8-1-3", fingerprint.TCP)
	assert.Equal(t, "64", fingerprint.TTL)
}

func TestFingerprint_SetClientHelloCaptures(t *testing.T) {
	testCases := []struct {
		desc  string
		file  string
		ja4   string
		tlsfp string
	}{
		{
			desc:  "TLS 1.2 without ALPN",
			file:  "tls12-no-alpn.bin",
			ja4:   "t12d190800_d83cc789557e_7af1ed941c26",
			tlsfp: "t12d190700_d83cc789557e_e8ab298402c8_30e06788707b",
		},
		{
			desc:  "Chrome",
			file:  "chrome.bin",
			ja4:   "t13d1516h2_8daaf6152771_e5627efa2ab1",
			tlsfp: "t13d1513h2_8daaf6152771_8b8af37844ec_30e06788707b",
		},
		{
			desc:  "Chrome resumed",
			file:  "chrome-resumed.bin",
			ja4:   "t13d1516h2_8daaf6152771_9b887d9acb53",
			tlsfp: "t13d1513h2_8daaf6152771_8b8af37844ec_30e06788707b",
		},
		{
			desc:  "Firefox",
			file:  "firefox.bin",
			ja4:   "t13d1715h2_5b57614c22b0_3d5424432f57",
			tlsfp: "t13d1712h2_5b57614c22b0_40c704383e9d_64e4e22bfa81",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			hello, err := os.ReadFile(filepath.Join("testdata", "clienthello", test.file))
			require.NoError(t, err)

			var fingerprint Fingerprint
			server := tls.Server(helloConn{Reader: bytes.NewReader(hello)}, &tls.Config{
				GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
					fingerprint.SetClientHello(info)
					return nil, errors.New("client hello read")
				},
			})
			require.Error(t, server.Handshake())

			assert.Equal(t, test.ja4, fingerprint.JA4)
			assert.Equal(t, test.tlsfp, fingerprint.TLSFP)
		})
	}
}

type helloConn struct {
	net.Conn
	io.Reader
}

func (c helloConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

func (c helloConn) Write(p []byte) (int, error) {
	return len(p), nil
}
