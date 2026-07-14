// Active Response: vòng lặp thứ 5 của Reporter — poll Orchestrator (qua
// Agent Manager) xem có remediation job đang chờ cho host này không, nếu có
// thì tải bundle nội dung đã ký (cache lại theo remediation_ref, bundle bất
// biến nên không bao giờ cần tải lại 2 lần), chuyển cho Executor (tiến trình
// RIÊNG, quyền cao hơn — xem ./executor/) qua Unix socket nội bộ, rồi báo kết
// quả thực thi ngược lại Orchestrator.
//
// Kill-switch THẬT của tính năng nằm ở Orchestrator
// (settings.active_response_enabled, mặc định TẮT) — Reporter ở đây không tự
// quyết định bật/tắt, chỉ đơn giản là poll đều đặn; khi tính năng tắt,
// Orchestrator luôn trả "không có job" (204) nên vòng lặp này gần như no-op.
//
// Executor CHỈ nói chuyện qua đúng 1 request/response JSON trên Unix socket
// rồi đóng kết nối (không phải protocol dài hạn) — cùng mô hình
// apps/agent/executor/server.go:handleConn đã có sẵn.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// executorDialTimeout chặn 1 lần dial treo vô hạn nếu socket tồn tại nhưng
// Executor không Accept() được (vd đang bận xử lý accept loop khác — thực tế
// khó xảy ra vì handleConn chạy trong goroutine riêng, nhưng vẫn cần 1 giới
// hạn cứng thay vì phó mặc net.Dial mặc định).
const executorDialTimeout = 10 * time.Second

// executorIOTimeout giới hạn TOÀN BỘ vòng đời 1 kết nối tới Executor (gửi
// envelope + đọc kết quả) — đủ dư so với EXECUTOR_REMEDIATE_TIMEOUT mặc định
// phía Executor (300s, xem apps/agent/executor/main.go) cộng thêm margin cho
// I/O JSON, để Reporter không bao giờ chờ Executor lâu hơn chính Executor tự
// cho phép remediation script chạy.
const executorIOTimeout = 6 * time.Minute

// maxBundleResponseBytes chặn Reporter cấp phát bộ nhớ không giới hạn nếu
// Agent Manager/Orchestrator (relay phía sau) trả về response khổng lồ cho
// content_tar_gz_b64 (lỗi hoặc bị chiếm quyền) — 64 MiB (base64) dư sức cho
// 1 bundle Ansible hợp lệ đã nén gzip (playbook + vài role nhỏ).
const maxBundleResponseBytes = 64 * 1024 * 1024

// claimResponse khớp response 200 của /remediate-jobs/claim (Agent Manager
// relay tới /internal/agent/remediate-jobs/claim trên Orchestrator) — TÊN
// FIELD JSON phải khớp tuyệt đối hợp đồng, không tự đổi.
type claimResponse struct {
	JobID          int    `json:"job_id"`
	ControlID      string `json:"control_id"`
	RemediationRef string `json:"remediation_ref"`
	DryRun         bool   `json:"dry_run"`
}

// bundleResponse khớp response 200 của /remediation-bundle.
type bundleResponse struct {
	RemediationRef  string `json:"remediation_ref"`
	ContentTarGzB64 string `json:"content_tar_gz_b64"`
	SignatureAscB64 string `json:"signature_asc_b64"`
}

// jobEnvelope là request Reporter gửi cho Executor qua Unix socket — PHẢI
// khớp tuyệt đối apps/agent/executor/server.go:jobEnvelope (field dry_run
// MỚI thêm so với scaffold hiện có). Không import trực tiếp package
// executor vì đó là `package main` riêng (binary khác) — 2 struct độc lập,
// khớp nhau bằng field JSON, không bằng kiểu Go.
type jobEnvelope struct {
	ControlID      string `json:"control_id"`
	RemediationRef string `json:"remediation_ref"`
	DryRun         bool   `json:"dry_run"`
}

// executionResult là response Executor trả về qua Unix socket — PHẢI khớp
// tuyệt đối apps/agent/executor/server.go:executionResult (đổi tên từ
// verifyResult của scaffold verify-only trước đây, thêm các field kết quả
// thực thi thật). Nếu Verified=false, Executed luôn false và các field thực
// thi (ExitCode/DiffOutput/BackupTarB64/LogTail) đều rỗng — Executor KHÔNG
// extract/chạy gì khi chữ ký không hợp lệ.
type executionResult struct {
	Verified          bool   `json:"verified"`
	SignerFingerprint string `json:"signer_fingerprint,omitempty"`
	Reason            string `json:"reason,omitempty"`
	Executed          bool   `json:"executed"`
	ExitCode          int    `json:"exit_code,omitempty"`
	DiffOutput        string `json:"diff_output,omitempty"`
	BackupTarB64      string `json:"backup_tar_b64,omitempty"`
	LogTail           string `json:"log_tail,omitempty"`
}

func runRemediateLoop(client *http.Client, cfg config) {
	log.Printf("bắt đầu vòng lặp Active Response (poll remediation job) mỗi %s tới %s", cfg.remediatePollInterval, cfg.managerURL)
	for {
		runProtected("remediate", func() { pollAndExecuteRemediation(client, cfg) })
		time.Sleep(cfg.remediatePollInterval)
	}
}

// pollAndExecuteRemediation claim đúng 1 job (nếu có), tải bundle, chuyển cho
// Executor, rồi báo kết quả. KHÔNG BAO GIỜ panic hay để lỗi thoát ra ngoài —
// mọi nhánh lỗi đều tự log + (khi đã claim được job) tự POST 1
// remediate-result báo lỗi, để job không bao giờ kẹt ở trạng thái "running"
// vĩnh viễn phía Orchestrator chỉ vì Reporter/Executor gặp sự cố cục bộ.
func pollAndExecuteRemediation(client *http.Client, cfg config) {
	job, ok, err := claimRemediationJob(client, cfg)
	if err != nil {
		log.Printf("claim remediation job lỗi: %v", err)
		return
	}
	if !ok {
		// Không có job đang chờ — nhánh phổ biến nhất mỗi lần poll (đặc biệt
		// khi active_response_enabled=false phía Orchestrator), cố ý KHÔNG
		// log để tránh làm ồn log mỗi AGENT_REMEDIATE_POLL_INTERVAL.
		return
	}
	log.Printf("nhận remediation job job_id=%d control_id=%s remediation_ref=%s dry_run=%v", job.JobID, job.ControlID, job.RemediationRef, job.DryRun)

	if err := ensureBundleCached(client, cfg, job.RemediationRef); err != nil {
		log.Printf("job_id=%d tải bundle nội dung lỗi: %v", job.JobID, err)
		reportRemediationInfraFailure(client, cfg, job, fmt.Sprintf("tải bundle nội dung thất bại: %v", err))
		return
	}

	result, err := executeViaExecutor(cfg, job)
	if err != nil {
		log.Printf("job_id=%d gọi Executor lỗi: %v", job.JobID, err)
		reportRemediationInfraFailure(client, cfg, job, fmt.Sprintf("gọi Executor thất bại: %v", err))
		return
	}

	if !result.Verified {
		log.Printf("job_id=%d Executor TỪ CHỐI thực thi (chữ ký không hợp lệ): %s", job.JobID, result.Reason)
		reportRemediationInfraFailure(client, cfg, job, fmt.Sprintf("Executor từ chối verify bundle: %s", result.Reason))
		return
	}

	if !result.Executed {
		// Verified=true nhưng Executed=false: lỗi hạ tầng phía Executor XẢY
		// RA SAU KHI verify chữ ký thành công (giải nén bundle lỗi, thiếu
		// playbook.yml, tạo thư mục tạm lỗi, backup TRƯỚC khi apply thất bại
		// — xem executionResult.Reason, apps/agent/executor/execute.go) —
		// KHÔNG có gì thực thi thật trên host. Nếu báo qua
		// reportRemediationResult bình thường, result.ExitCode giữ
		// zero-value Go (0) vì executionResult chỉ set ExitCode khi
		// Executed=true, khiến report_remediate_result (Orchestrator) hiểu
		// nhầm exit_code=0 là "thành công" — TRẠNG THÁI COMPLIANCE SAI dù
		// thực chất không có gì chạy (phát hiện qua rà soát đối kháng). Phải
		// báo qua nhánh lỗi hạ tầng, không phải kết quả thực thi.
		log.Printf("job_id=%d verify chữ ký OK nhưng KHÔNG thực thi được (lỗi hạ tầng): %s", job.JobID, result.Reason)
		reportRemediationInfraFailure(client, cfg, job, fmt.Sprintf("verify chữ ký OK nhưng thực thi thất bại: %s", result.Reason))
		return
	}

	if err := reportRemediationResult(client, cfg, job, result); err != nil {
		log.Printf("job_id=%d gửi remediate-result lỗi: %v", job.JobID, err)
		return
	}
	log.Printf("job_id=%d báo cáo kết quả remediation OK: exit_code=%d", job.JobID, result.ExitCode)
}

// claimRemediationJob POST /remediate-jobs/claim. Không dùng chung
// postAndExpect (chỉ check đúng 1 status) vì ở đây cần phân biệt 2 nhánh
// THÀNH CÔNG khác nhau: 204 (không có job — mirror hành vi heartbeat/scan
// hiện có ở agents.py) và 200 (có job, phải đọc tiếp body).
func claimRemediationJob(client *http.Client, cfg config) (claimResponse, bool, error) {
	reqBody, err := json.Marshal(map[string]string{"hostname": cfg.hostname})
	if err != nil {
		return claimResponse{}, false, err
	}
	resp, err := client.Post(cfg.managerURL+"/remediate-jobs/claim", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return claimResponse{}, false, fmt.Errorf("gọi Agent Manager thất bại: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return claimResponse{}, false, nil
	case http.StatusOK:
		var job claimResponse
		if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
			return claimResponse{}, false, fmt.Errorf("phản hồi claim không hợp lệ: %w", err)
		}
		return job, true, nil
	default:
		respBody, _ := io.ReadAll(resp.Body)
		return claimResponse{}, false, fmt.Errorf("Agent Manager từ chối claim (%d): %s", resp.StatusCode, string(respBody))
	}
}

// ensureBundleCached đảm bảo <cfg.contentCacheDir>/<remediationRef>/ chứa đủ
// content.tar.gz + content.tar.gz.sig, chỉ gọi mạng khi CHƯA có sẵn — bundle
// bất biến theo remediation_ref (tên bao gồm timestamp, xem quy ước
// scripts/content-signing/*.sh) nên cache-hit không bao giờ cần tải lại.
func ensureBundleCached(client *http.Client, cfg config, remediationRef string) error {
	bundleDir := filepath.Join(cfg.contentCacheDir, remediationRef)
	tarPath := filepath.Join(bundleDir, "content.tar.gz")
	sigPath := filepath.Join(bundleDir, "content.tar.gz.sig")
	if fileExists(tarPath) && fileExists(sigPath) {
		return nil
	}

	reqBody, err := json.Marshal(map[string]string{
		"hostname":        cfg.hostname,
		"remediation_ref": remediationRef,
	})
	if err != nil {
		return err
	}
	resp, err := client.Post(cfg.managerURL+"/remediation-bundle", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("gọi Agent Manager thất bại: %w", err)
	}
	defer resp.Body.Close()

	// io.LimitReader chặn Reporter cấp phát bộ nhớ không giới hạn nếu Agent
	// Manager/Orchestrator phía sau từng lỗi/bị chiếm quyền và trả về
	// response khổng lồ — Reporter là tiến trình quyền tối thiểu nhưng vẫn
	// là mắt xích bắt buộc của CẢ heartbeat/scan/FIM, OOM-kill nó ảnh hưởng
	// nhiều hơn chỉ riêng remediate (phát hiện qua rà soát đối kháng).
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleResponseBytes+1))
	if err != nil {
		return fmt.Errorf("đọc phản hồi bundle thất bại: %w", err)
	}
	if len(respBody) > maxBundleResponseBytes {
		return fmt.Errorf("phản hồi bundle vượt %d byte — từ chối (chống cấp phát bộ nhớ không giới hạn)", maxBundleResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Agent Manager từ chối tải bundle (%d): %s", resp.StatusCode, string(respBody))
	}

	var bundle bundleResponse
	if err := json.Unmarshal(respBody, &bundle); err != nil {
		return fmt.Errorf("phản hồi bundle không hợp lệ: %w", err)
	}

	tarBytes, err := base64.StdEncoding.DecodeString(bundle.ContentTarGzB64)
	if err != nil {
		return fmt.Errorf("content_tar_gz_b64 không decode được: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(bundle.SignatureAscB64)
	if err != nil {
		return fmt.Errorf("signature_asc_b64 không decode được: %w", err)
	}

	// 0770: chủ sở hữu (Reporter) đọc/ghi được, group (dùng chung với
	// Executor) đọc được, user khác trên máy thì không — cùng mô hình quyền
	// đã dùng cho socket Executor (xem executor/server.go:serve()).
	if err := os.MkdirAll(bundleDir, 0770); err != nil {
		return fmt.Errorf("tạo thư mục cache %s thất bại: %w", bundleDir, err)
	}
	// writeFileAtomic (đã có sẵn ở main.go) — tránh 1 file bundle nửa-vời nếu
	// process bị giết giữa chừng ghi, khiến lần poll sau lầm tưởng cache đã
	// đủ (fileExists true) trong khi nội dung thật sự bị cắt cụt.
	if err := writeFileAtomic(tarPath, tarBytes, 0660); err != nil {
		return fmt.Errorf("ghi content.tar.gz vào cache thất bại: %w", err)
	}
	if err := writeFileAtomic(sigPath, sigBytes, 0660); err != nil {
		return fmt.Errorf("ghi content.tar.gz.sig vào cache thất bại: %w", err)
	}
	return nil
}

// executeViaExecutor dial Unix socket của Executor, gửi đúng 1 job envelope,
// đọc đúng 1 executionResult rồi đóng kết nối — khớp protocol
// request-rồi-đóng của apps/agent/executor/server.go:handleConn.
func executeViaExecutor(cfg config, job claimResponse) (executionResult, error) {
	conn, err := net.DialTimeout("unix", cfg.executorSocketPath, executorDialTimeout)
	if err != nil {
		return executionResult{}, fmt.Errorf("dial Executor tại %s thất bại: %w", cfg.executorSocketPath, err)
	}
	defer conn.Close()

	// Deadline áp cho CẢ ghi lẫn đọc trên cùng kết nối — nếu Executor treo
	// (script remediation kẹt, tự chạy vượt EXECUTOR_REMEDIATE_TIMEOUT của
	// chính nó do bug...), Reporter phải tự bỏ cuộc thay vì chờ vô hạn, để
	// vòng lặp poll còn sống cho lần kế tiếp và job có thể được báo lỗi thay
	// vì kẹt "running" mãi mãi.
	if err := conn.SetDeadline(time.Now().Add(executorIOTimeout)); err != nil {
		return executionResult{}, fmt.Errorf("đặt deadline cho kết nối Executor thất bại: %w", err)
	}

	envelope := jobEnvelope{
		ControlID:      job.ControlID,
		RemediationRef: job.RemediationRef,
		DryRun:         job.DryRun,
	}
	if err := json.NewEncoder(conn).Encode(envelope); err != nil {
		return executionResult{}, fmt.Errorf("gửi job envelope tới Executor thất bại: %w", err)
	}

	var result executionResult
	if err := json.NewDecoder(conn).Decode(&result); err != nil {
		return executionResult{}, fmt.Errorf("đọc phản hồi Executor thất bại (treo hoặc đóng kết nối sớm?): %w", err)
	}
	return result, nil
}

// reportRemediationInfraFailure báo 1 lỗi hạ tầng phía Reporter/Executor (tải
// bundle lỗi, dial socket lỗi, timeout, verify chữ ký thất bại...) — LUÔN
// PHẢI gọi được dù chưa có executionResult thật nào, để job không kẹt
// "running" vĩnh viễn phía Orchestrator. exit_code cố định 1 (khác 0, đủ để
// Orchestrator đánh dấu job "failed") vì đây không phải exit code thật của
// remediation script.
func reportRemediationInfraFailure(client *http.Client, cfg config, job claimResponse, errMsg string) {
	body := map[string]any{
		"hostname":  cfg.hostname,
		"job_id":    job.JobID,
		"exit_code": 1,
		"dry_run":   job.DryRun,
		"log_tail":  "",
		"error":     errMsg,
	}
	if err := postAndExpect(client, cfg.managerURL+"/remediate-result", body, http.StatusOK); err != nil {
		log.Printf("job_id=%d gửi remediate-result báo lỗi hạ tầng (%q) cũng thất bại: %v", job.JobID, errMsg, err)
	}
}

// reportRemediationResult báo kết quả thực thi THẬT (Executor đã verify
// thành công và tự chạy remediation) về Orchestrator — mọi field lấy
// nguyên văn từ executionResult, KHÔNG tự cắt backup_tar_b64 ở đây: giới hạn
// BACKUP_MAX_BYTES là việc của Orchestrator (jobs.py — nguồn sự thật duy
// nhất cho việc cắt backup), Reporter/Executor không tự quyết định.
func reportRemediationResult(client *http.Client, cfg config, job claimResponse, result executionResult) error {
	body := map[string]any{
		"hostname":  cfg.hostname,
		"job_id":    job.JobID,
		"exit_code": result.ExitCode,
		"dry_run":   job.DryRun,
		"log_tail":  result.LogTail,
	}
	if result.DiffOutput != "" {
		body["diff_output"] = result.DiffOutput
	}
	if result.BackupTarB64 != "" {
		body["backup_tar_b64"] = result.BackupTarB64
	}
	return postAndExpect(client, cfg.managerURL+"/remediate-result", body, http.StatusOK)
}
