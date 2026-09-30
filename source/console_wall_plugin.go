package main

import (
	_ "embed"
	"fmt"
	"net/http"

	ludusapi "ludusapi"
	"ludusapi/pluginrpc"

	"github.com/pocketbase/pocketbase/core"
)

//go:embed ui/index.html
var consoleWallUI string

type ConsoleWallPlugin struct {
	server   *ludusapi.Server
	handlers map[string]func(*core.RequestEvent) error
}

func consoleWallRoutes() []pluginrpc.Route {
	return []pluginrpc.Route{
		{Name: "ConsoleWallInventory", Method: http.MethodGet, Pattern: "/console-wall/inventory"},
		{Name: "ConsoleWallScreenshot", Method: http.MethodGet, Pattern: "/console-wall/screenshot"},
		{Name: "ConsoleWallInput", Method: http.MethodPost, Pattern: "/console-wall/input"},
		{Name: "ConsoleWallSessionOpen", Method: http.MethodPost, Pattern: "/console-wall/session/open"},
		{Name: "ConsoleWallSessionFrame", Method: http.MethodGet, Pattern: "/console-wall/session/frame"},
		{Name: "ConsoleWallSessionInput", Method: http.MethodPost, Pattern: "/console-wall/session/input"},
		{Name: "ConsoleWallSessionClose", Method: http.MethodPost, Pattern: "/console-wall/session/close"},
	}
}

func (p *ConsoleWallPlugin) Metadata() (pluginrpc.Metadata, error) {
	return pluginrpc.Metadata{
		ID:          "console-wall-v120",
		Name:        "Ludus Console Wall",
		Version:     "1.2.0",
		Description: "A multi-range VM console wall with interactive Proxmox VNC and KasmVNC sessions.",
		Author:      "Ludus",
		Routes:      consoleWallRoutes(),
		UI:          &pluginrpc.UIContribution{HTML: consoleWallUI, RangeScoped: false},
	}, nil
}

func (p *ConsoleWallPlugin) Initialize(request pluginrpc.InitializeRequest) (pluginrpc.InitializeResponse, error) {
	server, err := ludusapi.InitializePluginRuntime(request)
	if err != nil {
		return pluginrpc.InitializeResponse{}, err
	}
	p.server = server
	p.handlers = map[string]func(*core.RequestEvent) error{
		"ConsoleWallInventory":    consoleWallInventory,
		"ConsoleWallScreenshot":   consoleWallScreenshot,
		"ConsoleWallInput":        consoleWallInput,
		"ConsoleWallSessionOpen":  liveSessionOpen,
		"ConsoleWallSessionFrame": liveSessionFrame,
		"ConsoleWallSessionInput": liveSessionInput,
		"ConsoleWallSessionClose": liveSessionClose,
	}
	liveSessions.start()
	return pluginrpc.InitializeResponse{State: ludusapi.PluginServerState(server)}, nil
}

func (p *ConsoleWallPlugin) Handle(request pluginrpc.Request) (pluginrpc.Response, error) {
	handler, ok := p.handlers[request.Route]
	if !ok {
		return pluginrpc.Response{}, fmt.Errorf("unknown Console Wall route %q", request.Route)
	}
	return ludusapi.RunPluginHandler(request, handler)
}

func (p *ConsoleWallPlugin) RunJob(string) (pluginrpc.JobResponse, error) {
	if p.server == nil {
		return pluginrpc.JobResponse{}, fmt.Errorf("Console Wall is not initialized")
	}
	return pluginrpc.JobResponse{State: ludusapi.PluginServerState(p.server)}, nil
}

func (p *ConsoleWallPlugin) Shutdown() error {
	liveSessions.shutdown()
	ludusapi.ClosePluginRuntime()
	return nil
}

func main() { pluginrpc.Serve(&ConsoleWallPlugin{}) }
