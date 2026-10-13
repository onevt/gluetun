package httpproxy

import (
	"io"
	"net"
	"net/http"
)

func (h *handler) handleHTTPS(responseWriter http.ResponseWriter, request *http.Request) {
	dialer := net.Dialer{}
	destinationConn, err := dialer.DialContext(h.ctx, "tcp", request.Host)
	if err != nil {
		http.Error(responseWriter, err.Error(), http.StatusServiceUnavailable)
		return
	}

	responseWriter.WriteHeader(http.StatusOK)

	hijacker, ok := responseWriter.(http.Hijacker)
	if !ok {
		http.Error(responseWriter, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConnection, clientBuffer, err := hijacker.Hijack()
	if err != nil {
		h.logger.Warn(err.Error())
		http.Error(responseWriter, err.Error(), http.StatusServiceUnavailable)
		if err := destinationConn.Close(); err != nil {
			h.logger.Error("closing destination connection: " + err.Error())
		}
		return
	}

	// Hijack flushes the 200 response, and the HTTP server may already have read
	// bytes the client sent after it, such as the start of a TLS client hello.
	// These are only in the hijack buffer and must be forwarded first.
	if buffered := clientBuffer.Reader.Buffered(); buffered > 0 {
		data, _ := clientBuffer.Reader.Peek(buffered)
		_, err = destinationConn.Write(data)
		if err != nil {
			h.logger.Warn("writing buffered client data to destination: " + err.Error())
			_ = clientConnection.Close()
			_ = destinationConn.Close()
			return
		}
	}

	if h.verbose {
		h.logger.Info(request.RemoteAddr + " <-> " + request.Host)
	}

	h.wg.Add(1)

	serverToClientDone := make(chan struct{})
	clientToServerClientDone := make(chan struct{})
	go transfer(destinationConn, clientConnection, clientToServerClientDone)
	go transfer(clientConnection, destinationConn, serverToClientDone)

	select {
	case <-h.ctx.Done():
		destinationConn.Close()
		clientConnection.Close()
		<-serverToClientDone
		<-clientToServerClientDone
	case <-serverToClientDone:
		<-clientToServerClientDone
	case <-clientToServerClientDone: // happens more rarely, when a connection is closed on the client side
		<-serverToClientDone
	}

	h.wg.Done()
}

func transfer(destination io.WriteCloser, source io.ReadCloser, done chan<- struct{}) {
	_, _ = io.Copy(destination, source)
	_ = source.Close()
	_ = destination.Close()
	close(done)
}
