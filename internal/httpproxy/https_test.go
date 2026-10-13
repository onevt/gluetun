package httpproxy

import (
	"context"
	"io"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopLogger struct{}

func (noopLogger) Debug(string) {}
func (noopLogger) Info(string)  {}
func (noopLogger) Warn(string)  {}
func (noopLogger) Error(string) {}

func Test_handleHTTPS_bufferedClientData(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	const payload = "client data sent right behind the CONNECT request"

	listenConfig := net.ListenConfig{}
	destination, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = destination.Close() })

	received := make(chan string, 1)
	go func() {
		conn, err := destination.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data := make([]byte, len(payload))
		_, _ = io.ReadFull(conn, data)
		received <- string(data)
	}()

	proxy := httptest.NewServer(newHandler(ctx, &sync.WaitGroup{}, noopLogger{}, false, false, "", ""))
	t.Cleanup(proxy.Close)

	dialer := net.Dialer{}
	client, err := dialer.DialContext(ctx, "tcp", proxy.Listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// Writing the payload together with the request, without waiting for the
	// 200 response, makes the proxy HTTP server buffer it before the hijack.
	host := destination.Addr().String()
	_, err = client.Write([]byte("CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n" + payload))
	require.NoError(t, err)

	select {
	case data := <-received:
		assert.Equal(t, payload, data)
	case <-time.After(time.Second):
		t.Fatal("destination did not receive the client data")
	}
}
