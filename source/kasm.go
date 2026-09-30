package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"image"
	"image/draw"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ludusconsolewall/rfb"

	"github.com/gorilla/websocket"
)

const (
	kasmPort     = "8444"
	kasmWSPath   = "/websockify"
	kasmUsername = "kali"
	kasmPassword = "password"
)

type kasmCapture struct {
	Data     []byte
	MimeType string
	Width    int
	Height   int
}

func limitKasmCapture(capture kasmCapture) (kasmCapture, error) {
	if len(capture.Data) <= 5<<20 {
		return capture, nil
	}
	decoded, _, err := image.Decode(bytes.NewReader(capture.Data))
	if err != nil {
		return kasmCapture{}, err
	}
	rgba := image.NewRGBA(decoded.Bounds())
	draw.Draw(rgba, rgba.Bounds(), decoded, decoded.Bounds().Min, draw.Src)
	frame, data, err := encodeBridgeFrame(rgba)
	if err != nil {
		return kasmCapture{}, err
	}
	return kasmCapture{Data: data, MimeType: "image/png", Width: frame.Bounds().Dx(), Height: frame.Bounds().Dy()}, nil
}

func captureKasmScreenshot(ctx context.Context, address string, maxWidth int) (kasmCapture, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return kasmCapture{}, fmt.Errorf("Kali VM has no valid IP address")
	}
	capture, err := captureKasmAPI(ctx, ip, maxWidth)
	if err == nil {
		return capture, nil
	}
	// KasmVNC 1.4.0 returns HTTP 400 until a viewer has initialized its
	// screenshot buffer. Open a short-lived viewer to capture that first frame.
	if !isKasmEmptyFrame(err) {
		return kasmCapture{}, err
	}
	capture, viewerErr := captureKasmViewer(ctx, ip, maxWidth)
	if viewerErr != nil {
		return kasmCapture{}, fmt.Errorf("KasmVNC screenshot API has no frame; viewer capture failed: %w", viewerErr)
	}
	return capture, nil
}

func captureKasmAPI(ctx context.Context, ip net.IP, maxWidth int) (kasmCapture, error) {
	target := url.URL{Scheme: "https", Host: net.JoinHostPort(ip.String(), kasmPort), Path: "/api/get_screenshot"}
	query := target.Query()
	query.Set("width", fmt.Sprint(maxWidth))
	query.Set("quality", "7")
	target.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return kasmCapture{}, err
	}
	request.SetBasicAuth(kasmUsername, kasmPassword)
	client := &http.Client{
		Timeout:   consoleCaptureTimeout,
		Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}, // KasmVNC uses its generated self-signed certificate.
	}
	response, err := client.Do(request)
	if err != nil {
		return kasmCapture{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxScreenshotBytes+1))
	if err != nil {
		return kasmCapture{}, err
	}
	if len(data) > maxScreenshotBytes {
		return kasmCapture{}, fmt.Errorf("screenshot exceeds the plugin response limit")
	}
	if response.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(data))
		if len(message) > 300 {
			message = message[:300]
		}
		if message == "" {
			message = response.Status
		}
		return kasmCapture{}, &kasmHTTPError{StatusCode: response.StatusCode, Message: message}
	}
	capture, err := parseKasmScreenshot(data)
	if err != nil {
		return kasmCapture{}, err
	}
	return capture, nil
}

type kasmHTTPError struct {
	StatusCode int
	Message    string
}

func (e *kasmHTTPError) Error() string {
	return fmt.Sprintf("KasmVNC returned HTTP %d: %s", e.StatusCode, e.Message)
}

func isKasmEmptyFrame(err error) bool {
	httpError, ok := err.(*kasmHTTPError)
	return ok && httpError.StatusCode == http.StatusBadRequest
}

func captureKasmViewer(ctx context.Context, ip net.IP, maxWidth int) (kasmCapture, error) {
	host := net.JoinHostPort(ip.String(), kasmPort)
	return captureKasmViewerAt(ctx, "wss://"+host+kasmWSPath, maxWidth)
}

func captureKasmViewerAt(ctx context.Context, viewerURL string, maxWidth int) (kasmCapture, error) {
	target, err := url.Parse(viewerURL)
	if err != nil || target.Host == "" {
		return kasmCapture{}, fmt.Errorf("invalid KasmVNC viewer URL")
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: 8 * time.Second,
		Subprotocols:     []string{"binary"},
		TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, // KasmVNC uses a generated self-signed certificate.
	}
	headers := http.Header{}
	headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(kasmUsername+":"+kasmPassword)))
	headers.Set("Origin", "https://"+target.Host)
	connection, response, err := dialer.DialContext(ctx, viewerURL, headers)
	if err != nil {
		if response != nil {
			return kasmCapture{}, fmt.Errorf("connect to KasmVNC viewer: %w (HTTP %d)", err, response.StatusCode)
		}
		return kasmCapture{}, fmt.Errorf("connect to KasmVNC viewer: %w", err)
	}
	defer connection.Close()
	// KasmVNC authenticates the WebSocket with Basic Auth and intentionally
	// configures an empty legacy RFB password behind that connection.
	client := rfb.New(&wallWSConn{conn: connection}, rfb.Options{})
	if err := client.Handshake(ctx); err != nil {
		return kasmCapture{}, fmt.Errorf("KasmVNC viewer handshake: %w", err)
	}
	frame, err := client.Screenshot(ctx)
	if err != nil {
		return kasmCapture{}, fmt.Errorf("KasmVNC viewer screenshot: %w", err)
	}
	frame = scaleToWidth(frame, maxWidth)
	data, err := encodeScreenshot(frame)
	if err != nil {
		return kasmCapture{}, err
	}
	if len(data) > maxScreenshotBytes {
		return kasmCapture{}, fmt.Errorf("KasmVNC viewer screenshot exceeds the plugin response limit")
	}
	return kasmCapture{Data: data, MimeType: "image/png", Width: frame.Bounds().Dx(), Height: frame.Bounds().Dy()}, nil
}

func parseKasmScreenshot(data []byte) (kasmCapture, error) {
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return kasmCapture{}, fmt.Errorf("decode screenshot: %w", err)
	}
	mimeType := http.DetectContentType(data)
	if format == "jpeg" {
		mimeType = "image/jpeg"
	} else if format == "png" {
		mimeType = "image/png"
	}
	return kasmCapture{Data: data, MimeType: mimeType, Width: config.Width, Height: config.Height}, nil
}
