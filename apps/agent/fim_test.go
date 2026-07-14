package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type recordedFimEvent struct {
	EventType string `json:"event_type"`
	Path      string `json:"path"`
	OldHash   string `json:"old_hash"`
	NewHash   string `json:"new_hash"`
}

func fimEventRecorder(t *testing.T) (*httptest.Server, func() []recordedFimEvent) {
	t.Helper()
	var mu sync.Mutex
	var events []recordedFimEvent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e recordedFimEvent
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			t.Errorf("body fim-event không phải JSON hợp lệ: %v", err)
		}
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	return srv, func() []recordedFimEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedFimEvent{}, events...)
	}
}

func TestRunFimOnce_FirstPassIsBaselineNoEvents(t *testing.T) {
	srv, getEvents := fimEventRecorder(t)
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "watched")
	os.WriteFile(path, []byte("v1"), 0600)

	cfg := config{managerURL: srv.URL, hostname: "h1", fimPaths: []string{path}}
	state := newFimState()
	runFimOnce(srv.Client(), cfg, state)

	if events := getEvents(); len(events) != 0 {
		t.Fatalf("lượt đầu (baseline) phải KHÔNG báo event, nhận %d", len(events))
	}
	if !state.baselineDone {
		t.Fatalf("baselineDone phải true sau lượt đầu")
	}
}

func TestRunFimOnce_DetectsModification(t *testing.T) {
	srv, getEvents := fimEventRecorder(t)
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "watched")
	os.WriteFile(path, []byte("v1"), 0600)

	cfg := config{managerURL: srv.URL, hostname: "h1", fimPaths: []string{path}}
	state := newFimState()
	runFimOnce(srv.Client(), cfg, state) // baseline

	os.WriteFile(path, []byte("v2-changed"), 0600)
	runFimOnce(srv.Client(), cfg, state)

	events := getEvents()
	if len(events) != 1 || events[0].EventType != "modified" {
		t.Fatalf("events = %+v, muốn đúng 1 event \"modified\"", events)
	}
	if events[0].OldHash == "" || events[0].NewHash == "" || events[0].OldHash == events[0].NewHash {
		t.Fatalf("old_hash/new_hash không hợp lệ: %+v", events[0])
	}
}

func TestRunFimOnce_DetectsDeletion(t *testing.T) {
	srv, getEvents := fimEventRecorder(t)
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "watched")
	os.WriteFile(path, []byte("v1"), 0600)

	cfg := config{managerURL: srv.URL, hostname: "h1", fimPaths: []string{path}}
	state := newFimState()
	runFimOnce(srv.Client(), cfg, state) // baseline

	os.Remove(path)
	runFimOnce(srv.Client(), cfg, state)

	events := getEvents()
	if len(events) != 1 || events[0].EventType != "deleted" {
		t.Fatalf("events = %+v, muốn đúng 1 event \"deleted\"", events)
	}
	if events[0].OldHash == "" || events[0].NewHash != "" {
		t.Fatalf("deleted event phải có old_hash, KHÔNG có new_hash: %+v", events[0])
	}
}

func TestRunFimOnce_DetectsCreationAfterBaseline(t *testing.T) {
	srv, getEvents := fimEventRecorder(t)
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "appears-later")

	cfg := config{managerURL: srv.URL, hostname: "h1", fimPaths: []string{path}}
	state := newFimState()
	runFimOnce(srv.Client(), cfg, state) // baseline — file chưa tồn tại, không có gì để báo

	os.WriteFile(path, []byte("new-file"), 0600)
	runFimOnce(srv.Client(), cfg, state)

	events := getEvents()
	if len(events) != 1 || events[0].EventType != "created" {
		t.Fatalf("events = %+v, muốn đúng 1 event \"created\"", events)
	}
	if events[0].NewHash == "" || events[0].OldHash != "" {
		t.Fatalf("created event phải có new_hash, KHÔNG có old_hash: %+v", events[0])
	}
}

func TestRunFimOnce_NoChangeNoEvent(t *testing.T) {
	srv, getEvents := fimEventRecorder(t)
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "watched")
	os.WriteFile(path, []byte("stable"), 0600)

	cfg := config{managerURL: srv.URL, hostname: "h1", fimPaths: []string{path}}
	state := newFimState()
	runFimOnce(srv.Client(), cfg, state) // baseline
	runFimOnce(srv.Client(), cfg, state) // không đổi gì

	if events := getEvents(); len(events) != 0 {
		t.Fatalf("file không đổi nhưng vẫn báo event: %+v", events)
	}
}

func TestHashFile_DifferentContentDifferentHash(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "a")
	p2 := filepath.Join(dir, "b")
	os.WriteFile(p1, []byte("content-a"), 0600)
	os.WriteFile(p2, []byte("content-b"), 0600)

	h1, err := hashFile(p1)
	if err != nil {
		t.Fatalf("hashFile(p1) lỗi: %v", err)
	}
	h2, err := hashFile(p2)
	if err != nil {
		t.Fatalf("hashFile(p2) lỗi: %v", err)
	}
	if h1 == h2 {
		t.Fatalf("2 file nội dung khác nhau nhưng hash giống nhau")
	}
}

func TestHashFile_MissingFileReturnsError(t *testing.T) {
	if _, err := hashFile("/no/such/file"); err == nil {
		t.Fatalf("hashFile không lỗi dù file không tồn tại")
	}
}
