package main

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/pocketbase/pocketbase/core"
	ludusapi "ludusapi"
	"ludusapi/models"
)

func accessibleWallRanges(e *core.RequestEvent) ([]*models.Range, error) {
	if e.Auth == nil {
		return nil, fmt.Errorf("authentication required")
	}
	user, ok := e.Get("user").(*models.User)
	if !ok || user == nil || user.Record == nil {
		return nil, fmt.Errorf("user record unavailable")
	}
	client, err := ludusapi.PluginPocketBase()
	if err != nil {
		return nil, err
	}
	found := map[string]*models.Range{}
	add := func(record *core.Record) {
		if record == nil || record.Id == "" {
			return
		}
		r := &models.Range{}
		r.SetProxyRecord(record)
		found[record.Id] = r
	}
	if e.Auth.IsSuperuser() || e.Auth.GetBool("isAdmin") {
		records, err := client.ListRecords(e.Request.Context(), "ranges", "")
		if err != nil {
			return nil, fmt.Errorf("list ranges: %w", err)
		}
		for _, record := range records {
			add(record)
		}
	} else {
		for _, r := range user.Ranges() {
			add(r.Record)
		}
		userID, _ := json.Marshal(user.Record.Id)
		groups, err := client.ListRecords(e.Request.Context(), "groups", "members.id ?= "+string(userID)+" || managers.id ?= "+string(userID), "ranges")
		if err != nil {
			return nil, fmt.Errorf("list range access groups: %w", err)
		}
		for _, group := range groups {
			for _, record := range group.ExpandedAll("ranges") {
				add(record)
			}
			for _, id := range group.GetStringSlice("ranges") {
				if _, ok := found[id]; ok {
					continue
				}
				record, err := client.FindRecordByID(e.Request.Context(), "ranges", id)
				if err != nil {
					return nil, fmt.Errorf("load group range: %w", err)
				}
				add(record)
			}
		}
	}
	ranges := make([]*models.Range, 0, len(found))
	for _, r := range found {
		ranges = append(ranges, r)
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].RangeNumber() != ranges[j].RangeNumber() {
			return ranges[i].RangeNumber() < ranges[j].RangeNumber()
		}
		return ranges[i].RangeId() < ranges[j].RangeId()
	})
	return ranges, nil
}

func findAccessibleWallVM(e *core.RequestEvent, vmid int) (*wallVM, error) {
	if vmid <= 0 {
		return nil, fmt.Errorf("invalid VMID")
	}
	ranges, err := accessibleWallRanges(e)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*models.Range, len(ranges))
	for _, r := range ranges {
		byID[r.Id] = r
	}
	client, err := ludusapi.PluginPocketBase()
	if err != nil {
		return nil, err
	}
	record, err := client.FindFirstRecordByData(e.Request.Context(), "vms", "proxmoxID", vmid)
	if err != nil {
		return nil, fmt.Errorf("VM is not part of an accessible range")
	}
	rng := byID[record.GetString("range")]
	if rng == nil {
		return nil, fmt.Errorf("VM is not part of an accessible range")
	}
	vm := &models.VM{}
	vm.SetProxyRecord(record)
	source := "proxmox"
	if isKasmVM(vm.Name(), loadWallTemplates(rng.RangeId())[vm.Name()]) {
		source = "kasm"
	}
	return &wallVM{RangeID: rng.RangeId(), RangeNumber: rng.RangeNumber(), Name: vm.Name(), IP: vm.Ip(), VMID: vm.ProxmoxId(), PoweredOn: vm.PoweredOn(), IsRouter: vm.IsRouter(), ConsoleSource: source}, nil
}
