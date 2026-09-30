package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	ludusapi "ludusapi"
	"ludusapi/models"
	"ludusapi/pluginrpc"
)

func TestAccessibleRangesIncludeGroupButRejectOtherVM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/groups/records"):
			_ = json.NewEncoder(w).Encode(map[string]any{"page": 1, "totalPages": 1, "items": []any{map[string]any{"id": "g2", "ranges": []string{"r2"}, "expand": map[string]any{"ranges": []any{map[string]any{"collectionName": "ranges", "id": "r2", "rangeID": "range-two", "rangeNumber": 2, "name": "Two"}}}}}})
		case strings.Contains(r.URL.Path, "/vms/records"):
			vmid := 0
			switch {
			case strings.Contains(r.URL.RawQuery, "101"):
				vmid = 101
			case strings.Contains(r.URL.RawQuery, "201"):
				vmid = 201
			case strings.Contains(r.URL.RawQuery, "301"):
				vmid = 301
			}
			rangeID := "r1"
			if vmid == 201 {
				rangeID = "r2"
			}
			if vmid == 301 {
				rangeID = "r3"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"page": 1, "totalPages": 1, "items": []any{map[string]any{"id": "vm", "proxmoxID": vmid, "range": rangeID, "name": "ubuntu", "ip": "10.1.0.10", "poweredOn": true}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	_, err := ludusapi.InitializePluginRuntime(pluginrpc.InitializeRequest{Configuration: []byte("{}"), PocketBase: pluginrpc.PocketBaseConnection{URL: server.URL, Token: "test-token"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ludusapi.ClosePluginRuntime()
	userRecord := core.NewRecord(core.NewAuthCollection("users"))
	userRecord.Id = "u1"
	userRecord.Set("userID", "alice")
	r1 := core.NewRecord(core.NewBaseCollection("ranges"))
	r1.Id = "r1"
	r1.Set("rangeID", "range-one")
	r1.Set("rangeNumber", 1)
	r1.Set("name", "One")
	userRecord.SetExpand(map[string]any{"ranges": []*core.Record{r1}})
	user := &models.User{}
	user.SetProxyRecord(userRecord)
	e := &core.RequestEvent{Event: router.Event{Request: httptest.NewRequest(http.MethodGet, "/", nil), Response: httptest.NewRecorder()}, Auth: userRecord}
	e.Set("user", user)
	ranges, err := accessibleWallRanges(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 || ranges[0].RangeId() != "range-one" || ranges[1].RangeId() != "range-two" {
		t.Fatalf("accessible ranges = %+v", ranges)
	}
	for _, vmid := range []int{101, 201} {
		vm, err := findAccessibleWallVM(e, vmid)
		if err != nil || vm.VMID != vmid {
			t.Fatalf("VM %d: %+v %v", vmid, vm, err)
		}
	}
	if _, err := findAccessibleWallVM(e, 301); err == nil {
		t.Fatal("other user's VM was accessible")
	}
}
