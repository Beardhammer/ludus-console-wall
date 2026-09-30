package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pocketbase/pocketbase/core"
)

func TestInteractiveKasmSession(t *testing.T) {
	result := make(chan error, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != kasmWSPath {
			http.NotFound(w, r)
			return
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(kasmUsername+":"+kasmPassword))
		if r.Header.Get("Authorization") != want {
			http.Error(w, "auth", 401)
			return
		}
		ws, err := (&websocket.Upgrader{Subprotocols: []string{"binary"}, CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			result <- err
			return
		}
		defer ws.Close()
		write := func(data []byte) error { return ws.WriteMessage(websocket.BinaryMessage, data) }
		read := func() ([]byte, error) { _, data, err := ws.ReadMessage(); return data, err }
		if err := write([]byte("RFB 003.008\n")); err != nil {
			result <- err
			return
		}
		if data, err := read(); err != nil || string(data) != "RFB 003.008\n" {
			result <- fmt.Errorf("version %q %v", data, err)
			return
		}
		if err := write([]byte{1, 1}); err != nil {
			result <- err
			return
		}
		if data, err := read(); err != nil || !bytes.Equal(data, []byte{1}) {
			result <- fmt.Errorf("security %v %v", data, err)
			return
		}
		if err := write([]byte{0, 0, 0, 0}); err != nil {
			result <- err
			return
		}
		if data, err := read(); err != nil || !bytes.Equal(data, []byte{1}) {
			result <- fmt.Errorf("client init %v %v", data, err)
			return
		}
		init := make([]byte, 24)
		init[1], init[3] = 2, 1
		if err := write(init); err != nil {
			result <- err
			return
		}
		for i := 0; i < 2; i++ {
			if _, err := read(); err != nil {
				result <- err
				return
			}
		}
		for _, down := range []byte{1, 0} {
			data, err := read()
			if err != nil || len(data) != 8 || data[0] != 4 || data[1] != down {
				result <- fmt.Errorf("key event %v %v", data, err)
				return
			}
		}
		request, err := read()
		if err != nil || len(request) != 10 || request[0] != 3 {
			result <- fmt.Errorf("frame request %v %v", request, err)
			return
		}
		update := []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 255, 0, 255, 0, 0, 0}
		result <- write(update)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := openKasmLiveSessionAt(ctx, "wss"+strings.TrimPrefix(server.URL, "https")+kasmWSPath)
	if err != nil {
		t.Fatal(err)
	}
	defer session.close()
	if err := session.client.SetKeyState(ctx, "a", true); err != nil {
		t.Fatal(err)
	}
	if err := session.client.SetKeyState(ctx, "a", false); err != nil {
		t.Fatal(err)
	}
	live := &wallLiveSession{connection: session, lastUsed: time.Now()}
	frame, err := live.frame(ctx, wallVM{VMID: 101, Name: "kali"})
	if err != nil {
		t.Fatal(err)
	}
	if frame.Width != 2 || frame.Height != 1 || frame.Screenshot == "" {
		t.Fatalf("bad frame %+v", frame)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestInteractiveSessionCannotBeHijacked(t *testing.T) {
	s := &wallLiveSession{id: "opaque-session", owner: "owner", vmid: 101, lastUsed: time.Now()}
	liveSessions.mu.Lock()
	liveSessions.sessions[s.id] = s
	liveSessions.mu.Unlock()
	defer func() { liveSessions.mu.Lock(); delete(liveSessions.sessions, s.id); liveSessions.mu.Unlock() }()
	e := &core.RequestEvent{Auth: core.NewRecord(core.NewAuthCollection("users"))}
	e.Auth.Id = "other-user"
	if _, _, err := authorisedLiveSession(e, s.id); err == nil {
		t.Fatal("another user accessed an interactive session")
	}
}
