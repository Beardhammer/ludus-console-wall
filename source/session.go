package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	ludusapi "ludusapi"
	"ludusapi/models"
	"ludusconsolewall/rfb"

	"github.com/gorilla/websocket"
	goproxmox "github.com/luthermonson/go-proxmox"
	"github.com/pocketbase/pocketbase/core"
)

type consoleSession struct {
	client *rfb.Client
	conn   *wallWSConn
	once   sync.Once
}

func (s *consoleSession) close() {
	s.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.client.ReleaseAll(ctx)
		_ = s.conn.Close()
	})
}

type wallWSConn struct {
	conn    *websocket.Conn
	pending []byte
}

func (w *wallWSConn) Read(p []byte) (int, error) {
	for len(w.pending) == 0 {
		messageType, message, err := w.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		if messageType == websocket.BinaryMessage {
			w.pending = message
		}
	}
	n := copy(p, w.pending)
	w.pending = w.pending[n:]
	return n, nil
}

func (w *wallWSConn) Write(p []byte) (int, error) {
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wallWSConn) SetReadDeadline(deadline time.Time) error {
	return w.conn.SetReadDeadline(deadline)
}
func (w *wallWSConn) SetWriteDeadline(deadline time.Time) error {
	return w.conn.SetWriteDeadline(deadline)
}
func (w *wallWSConn) Close() error { return w.conn.Close() }

func findConsoleVM(ctx context.Context, client *goproxmox.Client, vmID int) (*goproxmox.VirtualMachine, error) {
	cluster, err := client.Cluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("get cluster: %w", err)
	}
	resources, err := cluster.Resources(ctx, "vm")
	if err != nil {
		return nil, fmt.Errorf("list cluster VMs: %w", err)
	}
	nodeName := ""
	for _, resource := range resources {
		if resource.VMID == uint64(vmID) {
			nodeName = resource.Node
			break
		}
	}
	if nodeName == "" {
		return nil, fmt.Errorf("VMID %d was not found in Proxmox", vmID)
	}
	node, err := client.Node(ctx, nodeName)
	if err != nil {
		return nil, fmt.Errorf("get node %s: %w", nodeName, err)
	}
	vm, err := node.VirtualMachine(ctx, vmID)
	if err != nil {
		return nil, fmt.Errorf("get VM %d: %w", vmID, err)
	}
	return vm, nil
}

func openConsoleSession(ctx context.Context, e *core.RequestEvent, vm *goproxmox.VirtualMachine) (*consoleSession, error) {
	proxyCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	proxy, err := vm.VNCProxy(proxyCtx, &goproxmox.VNCConfig{Websocket: true, GeneratePassword: true})
	if err != nil {
		return nil, fmt.Errorf("create VNC proxy: %w", err)
	}

	user, ok := e.Get("user").(*models.User)
	if !ok || user == nil {
		return nil, fmt.Errorf("authenticated Ludus user is unavailable")
	}
	tokenSecret, err := ludusapi.DecryptStringFromDatabase(user.ProxmoxTokenSecret())
	if err != nil {
		return nil, fmt.Errorf("decrypt Proxmox token: %w", err)
	}
	endpoint := consoleProxmoxEndpoint()
	if endpoint == "" {
		return nil, fmt.Errorf("no Proxmox endpoint is configured")
	}
	endpoint = strings.TrimRight(endpoint, "/")
	endpoint = strings.Replace(endpoint, "https://", "wss://", 1)
	endpoint = strings.Replace(endpoint, "http://", "ws://", 1)
	wsURL := fmt.Sprintf("%s/api2/json/nodes/%s/qemu/%d/vncwebsocket?port=%d&vncticket=%s",
		endpoint, url.PathEscape(vm.Node), vm.VMID, proxy.Port, url.QueryEscape(proxy.Ticket))

	dialer := websocket.Dialer{
		Proxy: http.ProxyFromEnvironment, HandshakeTimeout: 8 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: ludusapi.ServerConfiguration.ProxmoxInvalidCert},
	}
	headers := http.Header{}
	headers.Set("Authorization", "PVEAPIToken="+user.ProxmoxTokenId()+"="+tokenSecret)
	connection, response, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		if response != nil {
			return nil, fmt.Errorf("dial VNC websocket: %w (HTTP %d)", err, response.StatusCode)
		}
		return nil, fmt.Errorf("dial VNC websocket: %w", err)
	}
	transport := &wallWSConn{conn: connection}
	client := rfb.New(transport, rfb.Options{Password: proxy.Password})
	if err := client.Handshake(ctx); err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("RFB handshake: %w", err)
	}
	return &consoleSession{client: client, conn: transport}, nil
}

func consoleProxmoxEndpoint() string {
	if len(ludusapi.ServerConfiguration.ProxmoxEndpoints) > 0 {
		return ludusapi.ServerConfiguration.ProxmoxEndpoints[0]
	}
	return ludusapi.ServerConfiguration.ProxmoxURL
}
