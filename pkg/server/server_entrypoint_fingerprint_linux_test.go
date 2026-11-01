//go:build linux

package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/static"
	tcprouter "github.com/traefik/traefik/v3/pkg/server/router/tcp"
)

func TestFingerprintHeaders(t *testing.T) {
	epConfig := &static.EntryPointsTransport{}
	epConfig.SetDefaults()

	entryPoint, err := NewTCPEntryPoint(t.Context(), "", &static.EntryPoint{
		Address:          ":0",
		Transport:        epConfig,
		ForwardedHeaders: &static.ForwardedHeaders{},
		HTTP2:            &static.HTTP2Config{},
		Fingerprint:      &static.Fingerprint{TCP: true},
	}, nil, nil)
	require.NoError(t, err)

	router, err := tcprouter.NewRouter(nil)
	require.NoError(t, err)

	router.SetHTTPHandler(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set(xTCPFingerprint, req.Header.Get(xTCPFingerprint))
		rw.WriteHeader(http.StatusOK)
	}))

	conn, err := startEntrypoint(t, entryPoint, router)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+entryPoint.listener.Addr().String(), http.NoBody)
	require.NoError(t, err)
	req.Header.Set(xTCPFingerprint, "spoofed")

	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	fingerprint := resp.Header.Get(xTCPFingerprint)
	assert.NotEmpty(t, fingerprint)
	assert.NotEqual(t, "spoofed", fingerprint)
}

func TestFingerprintTLSHeaders(t *testing.T) {
	certContent, err := localhostCert.Read()
	require.NoError(t, err)

	keyContent, err := localhostKey.Read()
	require.NoError(t, err)

	tlsCert, err := tls.X509KeyPair(certContent, keyContent)
	require.NoError(t, err)

	epConfig := &static.EntryPointsTransport{}
	epConfig.SetDefaults()

	entryPoint, err := NewTCPEntryPoint(t.Context(), "", &static.EntryPoint{
		Address:          ":0",
		Transport:        epConfig,
		ForwardedHeaders: &static.ForwardedHeaders{},
		HTTP2:            &static.HTTP2Config{},
		Fingerprint:      &static.Fingerprint{},
	}, nil, nil)
	require.NoError(t, err)

	router, err := tcprouter.NewRouter(nil)
	require.NoError(t, err)

	router.SetHTTPSHandler(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set(xJA4, req.Header.Get(xJA4))
		rw.Header().Set(xTLSFP, req.Header.Get(xTLSFP))
		rw.WriteHeader(http.StatusOK)
	}), &tls.Config{Certificates: []tls.Certificate{tlsCert}})

	conn, err := startEntrypoint(t, entryPoint, router)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+entryPoint.listener.Addr().String(), http.NoBody)
	require.NoError(t, err)
	req.Header.Set(xJA4, "spoofed")
	req.Header.Set(xTLSFP, "spoofed")

	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	ja4 := resp.Header.Get(xJA4)
	assert.NotEmpty(t, ja4)
	assert.NotEqual(t, "spoofed", ja4)

	tlsfp := resp.Header.Get(xTLSFP)
	assert.NotEmpty(t, tlsfp)
	assert.NotEqual(t, "spoofed", tlsfp)
}
