// Scan runner cục bộ cho Reporter — chạy `oscap xccdf eval` NGAY trên máy
// đang chạy agent (không qua SSH như apps/execution-env/scan.sh), tái dùng
// đúng quy ước exit-code/parse kết quả với script đó để 2 nguồn dữ liệu
// (agentless qua Orchestrator, agent-based qua Reporter) có shape giống
// nhau trong bảng jobs.result_summary.
package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type xccdfRule struct {
	ID    string `xml:"id,attr"`
	Title string `xml:"title"`
}

type xccdfRuleResult struct {
	IDRef    string `xml:"idref,attr"`
	Severity string `xml:"severity,attr"`
	Result   string `xml:"result"`
}

type ruleFinding struct {
	RuleID   string `json:"rule_id"`
	Title    string `json:"title"`
	Result   string `json:"result"`
	Severity string `json:"severity"`
}

// parseXCCDFResults quét TOÀN BỘ document tìm phần tử <Rule> (map id->title)
// và <rule-result> (idref/result/severity), CHỈ giữ lại pass/fail — bỏ qua
// notapplicable/error/unknown, đúng như apps/execution-env/scan.sh (Python
// ElementTree). Dùng dec.DecodeElement trên từng StartElement thay vì decode
// nguyên struct gốc: XCCDF namespace-qualify mọi phần tử
// (xccdf-1.2:rule-result...) nhưng encoding/xml so khớp theo local name khi
// tag không khai báo namespace, nên không cần biết trước prefix namespace —
// đã verify bằng test thật với fixture có namespace (xem scan_test.go).
func parseXCCDFResults(path string) ([]ruleFinding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := xml.NewDecoder(f)
	titles := map[string]string{}
	var findings []ruleFinding

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse XML lỗi: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "Rule":
			var r xccdfRule
			if err := dec.DecodeElement(&r, &se); err == nil && r.ID != "" {
				titles[r.ID] = strings.TrimSpace(r.Title)
			}
		case "rule-result":
			var rr xccdfRuleResult
			if err := dec.DecodeElement(&rr, &se); err == nil {
				result := strings.TrimSpace(rr.Result)
				if result == "pass" || result == "fail" {
					findings = append(findings, ruleFinding{
						RuleID:   rr.IDRef,
						Title:    titles[rr.IDRef],
						Result:   result,
						Severity: rr.Severity,
					})
				}
			}
		}
	}
	return findings, nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// performLocalScan chạy `oscap xccdf eval` local và trả về result_summary
// dùng chung shape với job agentless (`jobs.py:_parse_scan_summary`):
// scan_job_status, scan_result_pass/fail, findings, findings_count. Không
// bao giờ trả error Go — mọi lỗi (kể cả lỗi thực thi oscap) được gói vào
// chính result_summary (scan_job_status="error") để luôn có cái gì đó báo
// cáo lên Orchestrator thay vì im lặng bỏ qua 1 chu kỳ scan.
func performLocalScan(cfg config) map[string]any {
	tmpDir, err := os.MkdirTemp("", "agent-scan-")
	if err != nil {
		return map[string]any{"scan_job_status": "error", "error": err.Error()}
	}
	defer os.RemoveAll(tmpDir)
	resultsPath := filepath.Join(tmpDir, "results.xml")

	// exec.Command (không context) chờ vô thời hạn — 1 lần oscap treo (content
	// hỏng/quá lớn, I/O bị khoá...) sẽ kẹt vòng lặp scan mãi mãi, không có gì
	// tự phát hiện/kill (phát hiện qua rà soát bảo mật, không phải test thật —
	// môi trường test không tái tạo được oscap treo thật).
	ctx, cancel := context.WithTimeout(context.Background(), cfg.scanTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "oscap", "xccdf", "eval",
		"--profile", cfg.scapProfile,
		"--results", resultsPath,
		cfg.scapDatastream)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	// exec.CommandContext mặc định chỉ Kill() đúng 1 tiến trình (oscap trực
	// tiếp) khi hết timeout. Nếu oscap tự fork thêm tiến trình con, con đó
	// vẫn giữ đầu ghi của pipe stdout/stderr mở sau khi tiến trình cha bị
	// kill, khiến cmd.Wait() TREO tới khi tiến trình con tự thoát — bỏ qua
	// timeout hoàn toàn (phát hiện qua test thật với fake oscap gọi
	// `sleep`, tái tạo đúng tình huống fork; xác nhận qua thực nghiệm trên
	// lab server, không chỉ suy luận). Đặt process group riêng + kill cả
	// group khi Cancel để không tiến trình con nào sống sót giữ pipe mở.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second

	if startErr := cmd.Start(); startErr != nil {
		return map[string]any{"scan_job_status": "error", "error": startErr.Error()}
	}
	// Hạ nice value của oscap để không giành CPU với các tiến trình khác
	// trên host (oscap là CPU-bound, không I/O-bound, nên chỉ cần hạ CPU
	// scheduling priority — không xử lý ioprio_set, chấp nhận là gap v1).
	// Best-effort: lỗi ở đây không nên chặn scan, chỉ log cảnh báo.
	if prioErr := syscall.Setpriority(syscall.PRIO_PROCESS, cmd.Process.Pid, 10); prioErr != nil {
		log.Printf("cảnh báo: không hạ được nice value của oscap: %v", prioErr)
	}
	runErr := cmd.Wait()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return map[string]any{
			"scan_job_status": "error",
			"error":           fmt.Sprintf("oscap vượt timeout %s, đã bị kill", cfg.scanTimeout),
			"output_tail":     tail(outBuf.String(), 2000),
		}
	}

	exitCode := 0
	if runErr != nil {
		exitErr, ok := runErr.(*exec.ExitError)
		if !ok {
			return map[string]any{"scan_job_status": "error", "error": runErr.Error()}
		}
		exitCode = exitErr.ExitCode()
	}

	// oscap: 0 = tất cả pass/notapplicable, 2 = có rule fail (kết quả hợp lệ,
	// KHÔNG phải lỗi thực thi), mã khác là lỗi thật (content sai, thiếu
	// quyền...) — cùng quy ước với apps/execution-env/scan.sh.
	if exitCode != 0 && exitCode != 2 {
		return map[string]any{
			"scan_job_status": "error",
			"exit_code":       exitCode,
			"output_tail":     tail(outBuf.String(), 2000),
		}
	}
	if _, statErr := os.Stat(resultsPath); statErr != nil {
		return map[string]any{
			"scan_job_status": "error",
			"error":           "không tạo được file kết quả",
			"output_tail":     tail(outBuf.String(), 2000),
		}
	}

	findings, err := parseXCCDFResults(resultsPath)
	if err != nil {
		return map[string]any{"scan_job_status": "error", "error": err.Error()}
	}
	passCount, failCount := 0, 0
	for _, f := range findings {
		if f.Result == "pass" {
			passCount++
		} else {
			failCount++
		}
	}
	return map[string]any{
		"scan_job_status":   "completed",
		"exit_code":         exitCode,
		"scan_result_pass":  fmt.Sprintf("%d", passCount),
		"scan_result_fail":  fmt.Sprintf("%d", failCount),
		"findings":          findings,
		"findings_count":    len(findings),
	}
}

func runScanLoop(client *http.Client, cfg config) {
	log.Printf("bắt đầu vòng lặp scan OpenSCAP mỗi %s (profile=%s)", cfg.scanInterval, cfg.scapProfile)
	for {
		runProtected("scan", func() { runScanOnce(client, cfg) })
		time.Sleep(cfg.scanInterval)
	}
}

func runScanOnce(client *http.Client, cfg config) {
	summary := performLocalScan(cfg)
	body := map[string]any{
		"hostname":       cfg.hostname,
		"scap_profile":   cfg.scapProfile,
		"result_summary": summary,
	}
	if err := postAndExpect(client, cfg.managerURL+"/scan-result", body, http.StatusCreated); err != nil {
		log.Printf("gửi kết quả scan lỗi: %v", err)
		return
	}
	log.Printf("scan OK: status=%v pass=%v fail=%v", summary["scan_job_status"], summary["scan_result_pass"], summary["scan_result_fail"])
}
