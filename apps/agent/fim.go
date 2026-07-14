// FIM (File Integrity Monitoring) tối giản cho Reporter — so sánh hash định
// kỳ (MVP theo đúng mục 4.3 architecture-proposal.md: "FIM: MVP dùng so
// sánh hash định kỳ (đơn giản); nâng lên inotify real-time ở giai đoạn sau
// nếu cần"). Agent KHÔNG có state lưu qua lần restart (không DB cục bộ) —
// mỗi lần process khởi động lại, lượt quét ĐẦU TIÊN là baseline (không báo
// event), chỉ so sánh với các lượt SAU trong cùng vòng đời process.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type fimState struct {
	mu           sync.Mutex
	hashes       map[string]string
	baselineDone bool
}

func newFimState() *fimState {
	return &fimState{hashes: map[string]string{}}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func runFimLoop(client *http.Client, cfg config) {
	log.Printf("bắt đầu vòng lặp FIM mỗi %s cho %d path (baseline lượt đầu, không báo event)", cfg.fimInterval, len(cfg.fimPaths))
	state := newFimState()
	for {
		runProtected("fim", func() { runFimOnce(client, cfg, state) })
		time.Sleep(cfg.fimInterval)
	}
}

func runFimOnce(client *http.Client, cfg config, state *fimState) {
	state.mu.Lock()
	defer state.mu.Unlock()

	for _, path := range cfg.fimPaths {
		newHash, statErr := hashFile(path)
		oldHash, hadOld := state.hashes[path]

		switch {
		case statErr != nil && hadOld:
			delete(state.hashes, path)
			reportFimEvent(client, cfg, path, "deleted", &oldHash, nil)
		case statErr == nil && !hadOld:
			state.hashes[path] = newHash
			if state.baselineDone {
				reportFimEvent(client, cfg, path, "created", nil, &newHash)
			}
		case statErr == nil && hadOld && oldHash != newHash:
			state.hashes[path] = newHash
			reportFimEvent(client, cfg, path, "modified", &oldHash, &newHash)
		}
		// statErr != nil && !hadOld: path chưa từng thấy, vẫn không đọc được
		// — không có gì để báo cáo, không phải thay đổi trạng thái.
	}
	state.baselineDone = true
}

func reportFimEvent(client *http.Client, cfg config, path, eventType string, oldHash, newHash *string) {
	body := map[string]any{
		"hostname":   cfg.hostname,
		"path":       path,
		"event_type": eventType,
	}
	if oldHash != nil {
		body["old_hash"] = *oldHash
	}
	if newHash != nil {
		body["new_hash"] = *newHash
	}
	if err := postAndExpect(client, cfg.managerURL+"/fim-event", body, http.StatusCreated); err != nil {
		log.Printf("gửi FIM event (%s %s) lỗi: %v", eventType, path, err)
		return
	}
	log.Printf("FIM event: %s %s", eventType, path)
}
