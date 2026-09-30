package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	ludusapi "ludusapi"
	"ludusapi/models"
	"ludusconsolewall/rfb"

	"github.com/pocketbase/pocketbase/core"
	yaml "sigs.k8s.io/yaml"
)

const (
	consoleCaptureTimeout = 30 * time.Second
	maxScreenshotBytes    = 8 << 20
	maxConsoleSessions    = 4
)

var (
	consoleSessionSem = make(chan struct{}, maxConsoleSessions)
	consoleVMLocks    sync.Map
)

type wallVM struct {
	RangeID       string `json:"rangeID"`
	RangeNumber   int    `json:"rangeNumber"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	VMID          int    `json:"vmid"`
	PoweredOn     bool   `json:"poweredOn"`
	IsRouter      bool   `json:"isRouter"`
	ConsoleSource string `json:"consoleSource"`
}

type wallInventory struct {
	RangeID string      `json:"rangeID"`
	Ranges  []wallRange `json:"ranges"`
	VMs     []wallVM    `json:"vms"`
}

type wallRange struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Number  int    `json:"number"`
	VMCount int    `json:"vmCount"`
}

type wallScreenshotResponse struct {
	VMID         int    `json:"vmid"`
	VMName       string `json:"vmName"`
	Width        int    `json:"width"`
	Height       int    `json:"height"`
	SourceWidth  int    `json:"sourceWidth"`
	SourceHeight int    `json:"sourceHeight"`
	CapturedAt   string `json:"capturedAt"`
	Screenshot   string `json:"screenshot"`
	MimeType     string `json:"mimeType"`
}

type wallRangeConfig struct {
	Ludus []struct {
		VMName   string `json:"vm_name"`
		Template string `json:"template"`
	} `json:"ludus"`
}

type wallInputAction struct {
	Type    string   `json:"type"`
	Key     string   `json:"key,omitempty"`
	Keys    []string `json:"keys,omitempty"`
	Text    string   `json:"text,omitempty"`
	X       int      `json:"x,omitempty"`
	Y       int      `json:"y,omitempty"`
	Button  string   `json:"button,omitempty"`
	Pressed bool     `json:"pressed,omitempty"`
	DeltaX  int      `json:"deltaX,omitempty"`
	DeltaY  int      `json:"deltaY,omitempty"`
	Count   int      `json:"count,omitempty"`
}

type wallInputRequest struct {
	VMID    int               `json:"vmid"`
	Actions []wallInputAction `json:"actions"`
}

func consoleWallInventory(e *core.RequestEvent) error {
	inventory, err := loadWallInventory(e)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusInternalServerError, err.Error())
	}
	return e.JSON(http.StatusOK, inventory)
}

func consoleWallScreenshot(e *core.RequestEvent) error {
	vmID, err := strconv.Atoi(e.Request.URL.Query().Get("vmid"))
	if err != nil || vmID <= 0 {
		return ludusapi.JSONError(e, http.StatusBadRequest, "vmid must be a positive integer")
	}
	maxWidth := 640
	if value := e.Request.URL.Query().Get("maxWidth"); value != "" {
		parsed, parseErr := strconv.Atoi(value)
		if parseErr != nil || parsed < 320 || parsed > 1920 {
			return ludusapi.JSONError(e, http.StatusBadRequest, "maxWidth must be between 320 and 1920")
		}
		maxWidth = parsed
	}

	selected, err := findAccessibleWallVM(e, vmID)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusForbidden, err.Error())
	}
	if !selected.PoweredOn {
		return ludusapi.JSONError(e, http.StatusConflict, "VM is powered off")
	}

	mutex, _ := consoleVMLocks.LoadOrStore(vmID, &sync.Mutex{})
	vmMutex := mutex.(*sync.Mutex)
	if !vmMutex.TryLock() {
		return ludusapi.JSONError(e, http.StatusConflict, "a capture for this VM is already in progress")
	}
	defer vmMutex.Unlock()
	select {
	case consoleSessionSem <- struct{}{}:
		defer func() { <-consoleSessionSem }()
	default:
		return ludusapi.JSONError(e, http.StatusTooManyRequests, "too many console captures are already running")
	}

	ctx, cancel := context.WithTimeout(e.Request.Context(), consoleCaptureTimeout)
	defer cancel()
	if selected.ConsoleSource == "kasm" {
		if !validWallRangeIP(selected.IP, selected.RangeNumber) {
			return ludusapi.JSONError(e, 403, "Kasm address is outside its range")
		}
		capture, captureErr := captureKasmScreenshot(ctx, selected.IP, maxWidth)
		if captureErr != nil {
			return ludusapi.JSONError(e, http.StatusBadGateway, "capture KasmVNC console: "+captureErr.Error())
		}
		sourceWidth, sourceHeight := capture.Width, capture.Height
		capture, captureErr = limitKasmCapture(capture)
		if captureErr != nil {
			return ludusapi.JSONError(e, http.StatusBadGateway, "resize KasmVNC console: "+captureErr.Error())
		}
		return e.JSON(http.StatusOK, wallScreenshotResponse{
			VMID: vmID, VMName: selected.Name, Width: capture.Width, Height: capture.Height,
			SourceWidth: sourceWidth, SourceHeight: sourceHeight, CapturedAt: time.Now().UTC().Format(time.RFC3339),
			Screenshot: base64.StdEncoding.EncodeToString(capture.Data), MimeType: capture.MimeType,
		})
	}
	client, err := ludusapi.GetGoProxmoxClientForUserUsingToken(e)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusInternalServerError, "get Proxmox client: "+err.Error())
	}
	vm, err := findConsoleVM(ctx, client, vmID)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusBadGateway, err.Error())
	}
	if !vm.IsRunning() {
		return ludusapi.JSONError(e, http.StatusConflict, "VM is not running")
	}

	session, err := openConsoleSession(ctx, e, vm)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusBadGateway, "open VM console: "+err.Error())
	}
	defer session.close()
	frame, err := session.client.Screenshot(ctx)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusBadGateway, "capture VM console: "+err.Error())
	}
	sourceWidth, sourceHeight := frame.Bounds().Dx(), frame.Bounds().Dy()
	frame = scaleToWidth(frame, maxWidth)
	frame, pngBytes, err := encodeBridgeFrame(frame)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusInternalServerError, "encode screenshot: "+err.Error())
	}
	if len(pngBytes) > maxScreenshotBytes {
		return ludusapi.JSONError(e, http.StatusRequestEntityTooLarge, "console screenshot exceeds the plugin response limit")
	}
	return e.JSON(http.StatusOK, wallScreenshotResponse{
		VMID: vmID, VMName: selected.Name, Width: frame.Bounds().Dx(), Height: frame.Bounds().Dy(),
		SourceWidth: sourceWidth, SourceHeight: sourceHeight,
		CapturedAt: time.Now().UTC().Format(time.RFC3339), Screenshot: base64.StdEncoding.EncodeToString(pngBytes), MimeType: "image/png",
	})
}

func consoleWallInput(e *core.RequestEvent) error {
	var request wallInputRequest
	if err := e.BindBody(&request); err != nil {
		return ludusapi.JSONError(e, http.StatusBadRequest, "invalid input request: "+err.Error())
	}
	if err := validateInputRequest(request); err != nil {
		return ludusapi.JSONError(e, http.StatusBadRequest, err.Error())
	}
	selected, err := findAccessibleWallVM(e, request.VMID)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusForbidden, err.Error())
	}
	if !selected.PoweredOn {
		return ludusapi.JSONError(e, http.StatusConflict, "VM is powered off")
	}
	if selected.ConsoleSource == "kasm" {
		return ludusapi.JSONError(e, http.StatusConflict, "KasmVNC consoles are view-only in Console Wall")
	}

	mutex, _ := consoleVMLocks.LoadOrStore(request.VMID, &sync.Mutex{})
	vmMutex := mutex.(*sync.Mutex)
	if !vmMutex.TryLock() {
		return ludusapi.JSONError(e, http.StatusConflict, "another console operation for this VM is in progress")
	}
	defer vmMutex.Unlock()
	select {
	case consoleSessionSem <- struct{}{}:
		defer func() { <-consoleSessionSem }()
	default:
		return ludusapi.JSONError(e, http.StatusTooManyRequests, "too many console operations are already running")
	}

	ctx, cancel := context.WithTimeout(e.Request.Context(), 45*time.Second)
	defer cancel()
	client, err := ludusapi.GetGoProxmoxClientForUserUsingToken(e)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusInternalServerError, "get Proxmox client: "+err.Error())
	}
	vm, err := findConsoleVM(ctx, client, request.VMID)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusBadGateway, err.Error())
	}
	if !vm.IsRunning() {
		return ludusapi.JSONError(e, http.StatusConflict, "VM is not running")
	}
	session, err := openConsoleSession(ctx, e, vm)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusBadGateway, "open VM console: "+err.Error())
	}
	defer session.close()
	if err := validateInputBounds(request.Actions, session.client.Width(), session.client.Height()); err != nil {
		return ludusapi.JSONError(e, http.StatusBadRequest, err.Error())
	}
	for i, action := range request.Actions {
		if err := runInputAction(ctx, session.client, action); err != nil {
			return ludusapi.JSONError(e, http.StatusBadGateway, fmt.Sprintf("action %d failed: %v", i+1, err))
		}
	}
	select {
	case <-ctx.Done():
		return ludusapi.JSONError(e, http.StatusGatewayTimeout, "input completed but screenshot timed out")
	case <-time.After(250 * time.Millisecond):
	}
	frame, err := session.client.Screenshot(ctx)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusBadGateway, "input completed but screenshot failed: "+err.Error())
	}
	sourceWidth, sourceHeight := frame.Bounds().Dx(), frame.Bounds().Dy()
	frame = scaleToWidth(frame, 1600)
	frame, pngBytes, err := encodeBridgeFrame(frame)
	if err != nil {
		return ludusapi.JSONError(e, http.StatusInternalServerError, "encode screenshot: "+err.Error())
	}
	if len(pngBytes) > maxScreenshotBytes {
		return ludusapi.JSONError(e, http.StatusRequestEntityTooLarge, "console screenshot exceeds the plugin response limit")
	}
	return e.JSON(http.StatusOK, wallScreenshotResponse{
		VMID: request.VMID, VMName: selected.Name, Width: frame.Bounds().Dx(), Height: frame.Bounds().Dy(),
		SourceWidth: sourceWidth, SourceHeight: sourceHeight, CapturedAt: time.Now().UTC().Format(time.RFC3339),
		Screenshot: base64.StdEncoding.EncodeToString(pngBytes), MimeType: "image/png",
	})
}

func validateInputRequest(request wallInputRequest) error {
	if request.VMID <= 0 {
		return fmt.Errorf("vmid must be a positive integer")
	}
	if len(request.Actions) == 0 || len(request.Actions) > 50 {
		return fmt.Errorf("actions must contain between 1 and 50 entries")
	}
	totalText := 0
	for i, action := range request.Actions {
		switch action.Type {
		case "key":
			if len(action.Keys) == 0 || len(action.Keys) > 5 {
				return fmt.Errorf("action %d: key requires 1 to 5 keys", i+1)
			}
			if _, _, err := rfb.ParseChordKeys(action.Keys); err != nil {
				return fmt.Errorf("action %d: %w", i+1, err)
			}
		case "type":
			if action.Text == "" {
				return fmt.Errorf("action %d: text is required", i+1)
			}
			totalText += len([]rune(action.Text))
		case "click":
			if action.X < 0 || action.Y < 0 {
				return fmt.Errorf("action %d: coordinates cannot be negative", i+1)
			}
			if action.Button != "" && action.Button != "left" && action.Button != "right" && action.Button != "middle" {
				return fmt.Errorf("action %d: unsupported mouse button", i+1)
			}
			if action.Count < 0 || action.Count > 2 {
				return fmt.Errorf("action %d: click count must be 1 or 2", i+1)
			}
		default:
			return fmt.Errorf("action %d: unsupported type %q", i+1, action.Type)
		}
	}
	if totalText > 4096 {
		return fmt.Errorf("typed text exceeds the 4096 character limit")
	}
	return nil
}

func validateInputBounds(actions []wallInputAction, width, height int) error {
	for i, action := range actions {
		if action.Type == "click" && (action.X >= width || action.Y >= height) {
			return fmt.Errorf("action %d: coordinates %d,%d are outside the %dx%d framebuffer", i+1, action.X, action.Y, width, height)
		}
	}
	return nil
}

func runInputAction(ctx context.Context, client *rfb.Client, action wallInputAction) error {
	switch action.Type {
	case "key":
		modifiers, key, err := rfb.ParseChordKeys(action.Keys)
		if err != nil {
			return err
		}
		return client.SendChord(ctx, modifiers, key)
	case "type":
		return client.Type(ctx, action.Text)
	case "click":
		if err := client.MoveTo(ctx, action.X, action.Y); err != nil {
			return err
		}
		button := rfb.ButtonLeft
		if action.Button == "right" {
			button = rfb.ButtonRight
		} else if action.Button == "middle" {
			button = rfb.ButtonMiddle
		}
		return client.Click(ctx, button, max(1, action.Count))
	}
	return nil
}

func loadWallInventory(e *core.RequestEvent) (wallInventory, error) {
	ranges, err := accessibleWallRanges(e)
	if err != nil {
		return wallInventory{}, err
	}
	client, err := ludusapi.PluginPocketBase()
	if err != nil {
		return wallInventory{}, err
	}
	inventory := wallInventory{Ranges: make([]wallRange, 0, len(ranges)), VMs: []wallVM{}}
	if rng, ok := e.Get("range").(*models.Range); ok && rng != nil {
		inventory.RangeID = rng.RangeId()
	}
	for _, rng := range ranges {
		rangeIDJSON, _ := json.Marshal(rng.Id)
		records, err := client.ListRecords(e.Request.Context(), "vms", "range = "+string(rangeIDJSON))
		if err != nil {
			return wallInventory{}, fmt.Errorf("list range %s VMs: %w", rng.RangeId(), err)
		}
		templates := loadWallTemplates(rng.RangeId())
		inventory.Ranges = append(inventory.Ranges, wallRange{ID: rng.RangeId(), Name: rng.Name(), Number: rng.RangeNumber(), VMCount: len(records)})
		for _, record := range records {
			vm := &models.VM{}
			vm.SetProxyRecord(record)
			source := "proxmox"
			if isKasmVM(vm.Name(), templates[vm.Name()]) {
				source = "kasm"
			}
			inventory.VMs = append(inventory.VMs, wallVM{RangeID: rng.RangeId(), RangeNumber: rng.RangeNumber(), Name: vm.Name(), IP: vm.Ip(), VMID: vm.ProxmoxId(), PoweredOn: vm.PoweredOn(), IsRouter: vm.IsRouter(), ConsoleSource: source})
		}
	}
	sort.Slice(inventory.VMs, func(i, j int) bool {
		if inventory.VMs[i].RangeID != inventory.VMs[j].RangeID {
			return inventory.VMs[i].RangeID < inventory.VMs[j].RangeID
		}
		if inventory.VMs[i].IsRouter != inventory.VMs[j].IsRouter {
			return inventory.VMs[i].IsRouter
		}
		return inventory.VMs[i].Name < inventory.VMs[j].Name
	})
	return inventory, nil
}

func loadWallTemplates(rangeID string) map[string]string {
	result := map[string]string{}
	if !filepath.IsLocal(rangeID) || filepath.Clean(rangeID) != rangeID {
		return result
	}
	root, err := filepath.EvalSymlinks(filepath.Join(ludusapi.LudusInstallPath, "ranges"))
	if err != nil {
		return result
	}
	path, err := filepath.EvalSymlinks(filepath.Join(root, rangeID, "range-config.yml"))
	if err != nil {
		return result
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return result
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	var config wallRangeConfig
	if yaml.Unmarshal(data, &config) != nil {
		return result
	}
	for _, item := range config.Ludus {
		name := strings.ReplaceAll(strings.ReplaceAll(item.VMName, "{{ range_id }}", rangeID), "{{range_id}}", rangeID)
		result[name] = item.Template
	}
	return result
}

func isKasmVM(name, template string) bool {
	value := strings.ToLower(name + " " + template)
	return strings.Contains(value, "kali") || strings.Contains(value, "kasm")
}

func validWallRangeIP(address string, rangeNumber int) bool {
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() || rangeNumber < 1 || rangeNumber > 255 {
		return false
	}
	octets := ip.As4()
	return octets[0] == 10 && int(octets[1]) == rangeNumber
}

func encodeScreenshot(frame *image.RGBA) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := encoder.Encode(&buffer, frame); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func encodeBridgeFrame(frame *image.RGBA) (*image.RGBA, []byte, error) {
	for _, width := range []int{frame.Bounds().Dx(), 1280, 960, 640} {
		frame = scaleToWidth(frame, width)
		data, err := encodeScreenshot(frame)
		if err != nil {
			return nil, nil, err
		}
		if len(data) <= 5<<20 {
			return frame, data, nil
		}
	}
	return nil, nil, fmt.Errorf("console frame exceeds the plugin bridge limit")
}

func scaleToWidth(source *image.RGBA, maxWidth int) *image.RGBA {
	width, height := source.Bounds().Dx(), source.Bounds().Dy()
	if width <= maxWidth || maxWidth <= 0 {
		return source
	}
	newHeight := max(1, height*maxWidth/width)
	target := image.NewRGBA(image.Rect(0, 0, maxWidth, newHeight))
	for y := 0; y < newHeight; y++ {
		sourceY := y * height / newHeight
		for x := 0; x < maxWidth; x++ {
			sourceX := x * width / maxWidth
			target.SetRGBA(x, y, source.RGBAAt(sourceX, sourceY))
		}
	}
	return target
}
