// Restore qua Agent — job "kind" thứ 2 dùng CHUNG vòng lặp claim/poll
// (runRemediateLoop, remediate.go) với remediate, chỉ khác Executor tự giải
// nén backup cục bộ thay vì verify GPG + chạy Ansible (xem
// executor/execute.go:executeRestore, app/jobs.py:run_restore).
package main

import (
	"log"
	"net/http"
)

// pollAndExecuteRestore xử lý 1 job "restore" đã claim được — mirror ĐÚNG
// nguyên tắc pollAndExecuteRemediation (KHÔNG BAO GIỜ panic/để lỗi thoát ra
// ngoài, luôn tự POST report để job không kẹt "running" vĩnh viễn phía
// Orchestrator dù Executor gặp sự cố cục bộ).
func pollAndExecuteRestore(client *http.Client, cfg config, job claimResponse) {
	log.Printf("nhận restore job job_id=%d", job.JobID)

	result, err := executeViaExecutor(cfg, job)
	if err != nil {
		log.Printf("job_id=%d gọi Executor (restore) lỗi: %v", job.JobID, err)
		reportRestoreResult(client, cfg, job.JobID, 1, "", err.Error())
		return
	}
	if !result.Executed {
		log.Printf("job_id=%d restore KHÔNG thực thi được: %s", job.JobID, result.Reason)
		reportRestoreResult(client, cfg, job.JobID, 1, result.LogTail, result.Reason)
		return
	}

	if err := reportRestoreResult(client, cfg, job.JobID, result.ExitCode, result.LogTail, ""); err != nil {
		log.Printf("job_id=%d gửi restore-result lỗi: %v", job.JobID, err)
		return
	}
	log.Printf("job_id=%d báo cáo kết quả restore OK: exit_code=%d", job.JobID, result.ExitCode)
}

// reportRestoreResult POST /restore-result — TÁCH RIÊNG khỏi
// reportRemediationResult/reportRemediationInfraFailure vì shape khác hẳn
// (không dry_run/diff_output/backup_tar_b64 mới, xem app/agents.py:
// report_restore_result). errMsg rỗng nghĩa là thành công, không có lỗi.
func reportRestoreResult(client *http.Client, cfg config, jobID, exitCode int, logTail, errMsg string) error {
	body := map[string]any{
		"hostname":  cfg.hostname,
		"job_id":    jobID,
		"exit_code": exitCode,
		"log_tail":  logTail,
	}
	if errMsg != "" {
		body["error"] = errMsg
	}
	return postAndExpect(client, cfg.managerURL+"/restore-result", body, http.StatusOK)
}
