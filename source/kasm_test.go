package main

import (
	"bytes"
	"context"
	"crypto/des"
	"encoding/base64"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestParseKasmScreenshot(t *testing.T) {
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 800, 450)), nil); err != nil {
		t.Fatal(err)
	}
	capture, err := parseKasmScreenshot(encoded.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if capture.Width != 800 || capture.Height != 450 || capture.MimeType != "image/jpeg" {
		t.Fatalf("unexpected capture metadata: %#v", capture)
	}
}

func TestParseKasmScreenshotRejectsNonImage(t *testing.T) {
	if _, err := parseKasmScreenshot([]byte("not an image")); err == nil {
		t.Fatal("non-image response was accepted")
	}
}

func TestKasmBadRequestFallsBackToViewer(t *testing.T) {
	if !isKasmEmptyFrame(&kasmHTTPError{StatusCode: http.StatusBadRequest}) {
		t.Fatal("HTTP 400 should trigger viewer capture")
	}
	if isKasmEmptyFrame(&kasmHTTPError{StatusCode: http.StatusUnauthorized}) {
		t.Fatal("authentication failure should not trigger viewer capture")
	}
}

func TestCaptureKasmViewer(t *testing.T) {
	serverErrors := make(chan error, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != kasmWSPath {
			http.NotFound(response, request)
			return
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(kasmUsername+":"+kasmPassword))
		if request.Header.Get("Authorization") != wantAuth || request.Header.Get("Origin") == "" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		upgrader := websocket.Upgrader{Subprotocols: []string{"binary"}, CheckOrigin: func(*http.Request) bool { return true }}
		connection, err := upgrader.Upgrade(response, request, nil)
		if err != nil {
			serverErrors <- err
			return
		}
		defer connection.Close()
		write := func(data []byte) bool {
			if err := connection.WriteMessage(websocket.BinaryMessage, data); err != nil {
				serverErrors <- err
				return false
			}
			return true
		}
		var lastMessage []byte
		read := func() bool {
			if _, lastMessage, err = connection.ReadMessage(); err != nil {
				serverErrors <- err
				return false
			}
			return true
		}
		if !write([]byte("RFB 003.008\n")) || !read() || !write([]byte{1, 2}) || !read() || !write(make([]byte, 16)) || !read() {
			return
		}
		block, _ := des.NewCipher(make([]byte, 8))
		wantResponse := make([]byte, 16)
		block.Encrypt(wantResponse[:8], make([]byte, 8))
		block.Encrypt(wantResponse[8:], make([]byte, 8))
		if !bytes.Equal(lastMessage, wantResponse) {
			serverErrors <- fmt.Errorf("viewer sent non-empty legacy RFB password response")
			return
		}
		if !write([]byte{0, 0, 0, 0}) || !read() {
			return
		}
		serverInit := make([]byte, 24)
		serverInit[1], serverInit[3] = 2, 1
		if !write(serverInit) || !read() || !read() || !read() {
			return
		}
		update := []byte{
			0, 0, 0, 1, // framebuffer update with one rectangle
			0, 0, 0, 0, 0, 2, 0, 1, // x, y, width, height
			0, 0, 0, 0, // raw encoding
			0, 0, 255, 0, 255, 0, 0, 0, // red then blue in BGRA
		}
		if write(update) {
			serverErrors <- nil
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	capture, err := captureKasmViewerAt(ctx, "wss"+strings.TrimPrefix(server.URL, "https")+kasmWSPath, 640)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverErrors; err != nil {
		t.Fatal(err)
	}
	if capture.MimeType != "image/png" || capture.Width != 2 || capture.Height != 1 {
		t.Fatalf("unexpected viewer capture: mime=%q size=%dx%d", capture.MimeType, capture.Width, capture.Height)
	}
	frame, err := png.Decode(bytes.NewReader(capture.Data))
	if err != nil {
		t.Fatal(err)
	}
	red, _, _, _ := frame.At(0, 0).RGBA()
	if red != 0xffff {
		t.Fatalf("first pixel red channel = %d", red)
	}
}
