package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pocketbase/pocketbase/core"
	ludusapi "ludusapi"
	"ludusconsolewall/rfb"
)

const maxLiveSessions = 6
const liveSessionTTL = 2 * time.Minute

type wallLiveSession struct {
	id, owner, rangeID, source string
	vmid                       int
	connection                 *consoleSession
	mu                         sync.Mutex
	lastUsed                   time.Time
	closed                     bool
}
type wallLiveManager struct {
	mu       sync.Mutex
	sessions map[string]*wallLiveSession
	stop     chan struct{}
	once     sync.Once
}

var liveSessions = wallLiveManager{sessions: map[string]*wallLiveSession{}, stop: make(chan struct{})}

func (m *wallLiveManager) start() {
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.prune()
			case <-m.stop:
				return
			}
		}
	}()
}
func (m *wallLiveManager) shutdown() {
	m.once.Do(func() { close(m.stop) })
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.close(id)
	}
}
func (m *wallLiveManager) prune() {
	m.mu.Lock()
	expired := []string{}
	for id, s := range m.sessions {
		s.mu.Lock()
		old := time.Since(s.lastUsed) > liveSessionTTL
		s.mu.Unlock()
		if old {
			expired = append(expired, id)
		}
	}
	m.mu.Unlock()
	for _, id := range expired {
		m.close(id)
	}
}
func (m *wallLiveManager) add(s *wallLiveSession) error {
	m.prune()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) >= maxLiveSessions {
		return fmt.Errorf("too many interactive consoles are open")
	}
	m.sessions[s.id] = s
	return nil
}
func (m *wallLiveManager) get(id string) *wallLiveSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id]
}
func (m *wallLiveManager) close(id string) {
	m.mu.Lock()
	s := m.sessions[id]
	delete(m.sessions, id)
	m.mu.Unlock()
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.connection.close()
	}
}

type wallSessionOpenRequest struct {
	VMID int `json:"vmid"`
}
type wallSessionRequest struct {
	SessionID string `json:"sessionID"`
}
type wallSessionInputRequest struct {
	SessionID string            `json:"sessionID"`
	Actions   []wallInputAction `json:"actions"`
}

func openKasmLiveSession(ctx context.Context, address string) (*consoleSession, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("KasmVNC VM has no valid IP address")
	}
	host := net.JoinHostPort(ip.String(), kasmPort)
	return openKasmLiveSessionAt(ctx, "wss://"+host+kasmWSPath)
}

func openKasmLiveSessionAt(ctx context.Context, viewerURL string) (*consoleSession, error) {
	target, err := url.Parse(viewerURL)
	if err != nil || target.Host == "" || (target.Scheme != "wss" && target.Scheme != "ws") {
		return nil, fmt.Errorf("invalid KasmVNC viewer URL")
	}
	dialer := websocket.Dialer{HandshakeTimeout: 8 * time.Second, Subprotocols: []string{"binary"}, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}
	headers := http.Header{}
	headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(kasmUsername+":"+kasmPassword)))
	headers.Set("Origin", "https://"+target.Host)
	conn, response, err := dialer.DialContext(ctx, viewerURL, headers)
	if err != nil {
		if response != nil {
			return nil, fmt.Errorf("KasmVNC viewer returned HTTP %d: %w", response.StatusCode, err)
		}
		return nil, err
	}
	transport := &wallWSConn{conn: conn}
	client := rfb.New(transport, rfb.Options{})
	if err := client.Handshake(ctx); err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("KasmVNC RFB handshake: %w", err)
	}
	return &consoleSession{client: client, conn: transport}, nil
}

func liveSessionOpen(e *core.RequestEvent) error {
	var body wallSessionOpenRequest
	if err := e.BindBody(&body); err != nil || body.VMID <= 0 {
		return ludusapi.JSONError(e, 400, "vmid must be a positive integer")
	}
	vm, err := findAccessibleWallVM(e, body.VMID)
	if err != nil {
		return ludusapi.JSONError(e, 403, err.Error())
	}
	if !vm.PoweredOn {
		return ludusapi.JSONError(e, 409, "VM is powered off")
	}
	ctx, cancel := context.WithTimeout(e.Request.Context(), 30*time.Second)
	defer cancel()
	var connection *consoleSession
	if vm.ConsoleSource == "kasm" {
		if !validWallRangeIP(vm.IP, vm.RangeNumber) {
			return ludusapi.JSONError(e, 403, "Kasm address is outside its range")
		}
		connection, err = openKasmLiveSession(ctx, vm.IP)
	} else {
		var clientErr error
		client, clientErr := ludusapi.GetGoProxmoxClientForUserUsingToken(e)
		if clientErr != nil {
			return ludusapi.JSONError(e, 500, clientErr.Error())
		}
		machine, findErr := findConsoleVM(ctx, client, vm.VMID)
		if findErr != nil {
			return ludusapi.JSONError(e, 502, findErr.Error())
		}
		if !machine.IsRunning() {
			return ludusapi.JSONError(e, 409, "VM is not running")
		}
		connection, err = openConsoleSession(ctx, e, machine)
	}
	if err != nil {
		return ludusapi.JSONError(e, 502, err.Error())
	}
	idBytes := make([]byte, 24)
	if _, err = rand.Read(idBytes); err != nil {
		connection.close()
		return ludusapi.JSONError(e, 500, "create session ID")
	}
	s := &wallLiveSession{id: hex.EncodeToString(idBytes), owner: e.Auth.Id, rangeID: vm.RangeID, source: vm.ConsoleSource, vmid: vm.VMID, connection: connection, lastUsed: time.Now()}
	if err = liveSessions.add(s); err != nil {
		connection.close()
		return ludusapi.JSONError(e, 429, err.Error())
	}
	frame, err := s.frame(ctx, *vm)
	if err != nil {
		liveSessions.close(s.id)
		return ludusapi.JSONError(e, 502, "capture first frame: "+err.Error())
	}
	return e.JSON(200, map[string]any{"sessionID": s.id, "frame": frame, "source": vm.ConsoleSource})
}

func (s *wallLiveSession) frame(ctx context.Context, vm wallVM) (wallScreenshotResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return wallScreenshotResponse{}, fmt.Errorf("session closed")
	}
	s.lastUsed = time.Now()
	frame, err := s.connection.client.Screenshot(ctx)
	if err != nil {
		return wallScreenshotResponse{}, err
	}
	sourceWidth, sourceHeight := frame.Bounds().Dx(), frame.Bounds().Dy()
	frame = scaleToWidth(frame, 1600)
	frame, data, err := encodeBridgeFrame(frame)
	if err != nil {
		return wallScreenshotResponse{}, err
	}
	if len(data) > maxScreenshotBytes {
		return wallScreenshotResponse{}, fmt.Errorf("frame exceeds response limit")
	}
	return wallScreenshotResponse{VMID: vm.VMID, VMName: vm.Name, Width: frame.Bounds().Dx(), Height: frame.Bounds().Dy(), SourceWidth: sourceWidth, SourceHeight: sourceHeight, CapturedAt: time.Now().UTC().Format(time.RFC3339), Screenshot: base64.StdEncoding.EncodeToString(data), MimeType: "image/png"}, nil
}

func authorisedLiveSession(e *core.RequestEvent, id string) (*wallLiveSession, wallVM, error) {
	if e.Auth == nil || id == "" {
		return nil, wallVM{}, fmt.Errorf("session unavailable")
	}
	s := liveSessions.get(id)
	if s == nil || s.owner != e.Auth.Id {
		return nil, wallVM{}, fmt.Errorf("session unavailable")
	}
	vm, err := findAccessibleWallVM(e, s.vmid)
	if err == nil && vm.RangeID == s.rangeID && vm.PoweredOn {
		return s, *vm, nil
	}
	liveSessions.close(id)
	return nil, wallVM{}, fmt.Errorf("VM access was removed or machine is powered off")
}

func liveSessionFrame(e *core.RequestEvent) error {
	id := e.Request.URL.Query().Get("sessionID")
	s, vm, err := authorisedLiveSession(e, id)
	if err != nil {
		return ludusapi.JSONError(e, 403, err.Error())
	}
	ctx, cancel := context.WithTimeout(e.Request.Context(), 25*time.Second)
	defer cancel()
	frame, err := s.frame(ctx, vm)
	if err != nil {
		liveSessions.close(id)
		return ludusapi.JSONError(e, 502, err.Error())
	}
	return e.JSON(200, frame)
}

func liveSessionInput(e *core.RequestEvent) error {
	var body wallSessionInputRequest
	if err := e.BindBody(&body); err != nil {
		return ludusapi.JSONError(e, 400, "invalid input request")
	}
	if len(body.Actions) == 0 || len(body.Actions) > 50 {
		return ludusapi.JSONError(e, 400, "actions must contain 1 to 50 entries")
	}
	s, _, err := authorisedLiveSession(e, body.SessionID)
	if err != nil {
		return ludusapi.JSONError(e, 403, err.Error())
	}
	ctx, cancel := context.WithTimeout(e.Request.Context(), 15*time.Second)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ludusapi.JSONError(e, 410, "session closed")
	}
	s.lastUsed = time.Now()
	textLength := 0
	for i, action := range body.Actions {
		if action.Type == "type" {
			textLength += len([]rune(action.Text))
		}
		if action.Type == "key" || action.Type == "type" || action.Type == "click" {
			if err := validateInputRequest(wallInputRequest{VMID: s.vmid, Actions: []wallInputAction{action}}); err != nil {
				return ludusapi.JSONError(e, 400, fmt.Sprintf("action %d: %v", i+1, err))
			}
		}
	}
	if textLength > 512 {
		return ludusapi.JSONError(e, 400, "typed text exceeds 512 characters per request")
	}
	for i, action := range body.Actions {
		if err := applyLiveAction(ctx, s.connection.client, action); err != nil {
			return ludusapi.JSONError(e, 400, fmt.Sprintf("action %d: %v", i+1, err))
		}
	}
	return e.JSON(200, map[string]any{"ok": true})
}

func applyLiveAction(ctx context.Context, client *rfb.Client, action wallInputAction) error {
	switch action.Type {
	case "keydown", "keyup":
		if action.Key == "" {
			return fmt.Errorf("key required")
		}
		return client.SetKeyState(ctx, action.Key, action.Type == "keydown")
	case "move":
		return client.SetPointerState(ctx, action.X, action.Y, 0, false)
	case "pointer":
		button := rfb.ButtonLeft
		switch action.Button {
		case "left":
		case "middle":
			button = rfb.ButtonMiddle
		case "right":
			button = rfb.ButtonRight
		default:
			return fmt.Errorf("unsupported pointer button")
		}
		return client.SetPointerState(ctx, action.X, action.Y, button, action.Pressed)
	case "scroll":
		if action.DeltaX > 5 || action.DeltaX < -5 || action.DeltaY > 5 || action.DeltaY < -5 {
			return fmt.Errorf("scroll step exceeds limit")
		}
		return client.Scroll(ctx, action.X, action.Y, action.DeltaX, action.DeltaY)
	case "key", "type", "click":
		return runInputAction(ctx, client, action)
	default:
		return fmt.Errorf("unsupported input type %q", action.Type)
	}
}

func liveSessionClose(e *core.RequestEvent) error {
	var body wallSessionRequest
	if err := e.BindBody(&body); err != nil {
		return ludusapi.JSONError(e, 400, "invalid close request")
	}
	s := liveSessions.get(body.SessionID)
	if s == nil {
		return e.JSON(200, map[string]any{"closed": true})
	}
	if e.Auth == nil || s.owner != e.Auth.Id {
		return ludusapi.JSONError(e, 403, "session unavailable")
	}
	liveSessions.close(body.SessionID)
	return e.JSON(200, map[string]any{"closed": true})
}
