//go:build linux

package server

import (
	"context"
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
