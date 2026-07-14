package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// xccdfFixture dùng namespace prefix "xccdf-1.2:" giống hệt output thật của
// `oscap xccdf eval` — verify rằng parseXCCDFResults (dùng dec.DecodeElement
// trên StartElement khớp local name) đọc đúng dù không biết trước prefix
// namespace, giống cách apps/execution-env/scan.sh (Python ElementTree với
// NS đầy đủ) đã làm ở phía agentless.
const xccdfFixture = `<?xml version="1.0" encoding="UTF-8"?>
<xccdf-1.2:Benchmark xmlns:xccdf-1.2="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test_benchmark">
  <xccdf-1.2:Rule id="xccdf_test_rule_1">
    <xccdf-1.2:title>Test Rule One</xccdf-1.2:title>
  </xccdf-1.2:Rule>
  <xccdf-1.2:Rule id="xccdf_test_rule_2">
    <xccdf-1.2:title>Test Rule Two</xccdf-1.2:title>
  </xccdf-1.2:Rule>
  <xccdf-1.2:TestResult id="xccdf_test_result">
    <xccdf-1.2:rule-result idref="xccdf_test_rule_1" severity="medium">
      <xccdf-1.2:result>pass</xccdf-1.2:result>
    </xccdf-1.2:rule-result>
    <xccdf-1.2:rule-result idref="xccdf_test_rule_2" severity="high">
      <xccdf-1.2:result>fail</xccdf-1.2:result>
    </xccdf-1.2:rule-result>
    <xccdf-1.2:rule-result idref="xccdf_test_rule_3" severity="low">
      <xccdf-1.2:result>notapplicable</xccdf-1.2:result>
    </xccdf-1.2:rule-result>
  </xccdf-1.2:TestResult>
</xccdf-1.2:Benchmark>
`

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "results.xml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("ghi fixture thất bại: %v", err)
	}
	return path
}

func TestParseXCCDFResults_KeepsOnlyPassAndFail(t *testing.T) {
	path := writeFixture(t, xccdfFixture)
	findings, err := parseXCCDFResults(path)
	if err != nil {
		t.Fatalf("parseXCCDFResults lỗi: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("số findings = %d, muốn 2 (notapplicable phải bị loại)", len(findings))
	}

	byRule := map[string]ruleFinding{}
	for _, f := range findings {
		byRule[f.RuleID] = f
	}

	r1, ok := byRule["xccdf_test_rule_1"]
	if !ok || r1.Result != "pass" || r1.Title != "Test Rule One" || r1.Severity != "medium" {
		t.Fatalf("rule_1 = %+v, ok=%v — sai title/result/severity", r1, ok)
	}
	r2, ok := byRule["xccdf_test_rule_2"]
	if !ok || r2.Result != "fail" || r2.Title != "Test Rule Two" || r2.Severity != "high" {
		t.Fatalf("rule_2 = %+v, ok=%v — sai title/result/severity", r2, ok)
	}
}

func TestParseXCCDFResults_MissingTitleFallsBackEmpty(t *testing.T) {
	// rule_3 có rule-result nhưng KHÔNG có <Rule id="...3"> tương ứng trong
	// fixture — vẫn phải bị loại vì result=notapplicable, nhưng nếu profile
	// khác có pass/fail cho 1 rule không rõ title thì Title phải là "" thay
	// vì panic/lỗi tra map.
	path := writeFixture(t, `<?xml version="1.0"?>
<xccdf-1.2:Benchmark xmlns:xccdf-1.2="http://checklists.nist.gov/xccdf/1.2">
  <xccdf-1.2:TestResult>
    <xccdf-1.2:rule-result idref="xccdf_unknown_rule" severity="low">
      <xccdf-1.2:result>fail</xccdf-1.2:result>
    </xccdf-1.2:rule-result>
  </xccdf-1.2:TestResult>
</xccdf-1.2:Benchmark>
`)
	findings, err := parseXCCDFResults(path)
	if err != nil {
		t.Fatalf("parseXCCDFResults lỗi: %v", err)
	}
	if len(findings) != 1 || findings[0].Title != "" {
		t.Fatalf("findings = %+v, muốn 1 phần tử với Title rỗng", findings)
	}
}

func TestParseXCCDFResults_MissingFileReturnsError(t *testing.T) {
	if _, err := parseXCCDFResults("/no/such/file.xml"); err == nil {
		t.Fatalf("parseXCCDFResults không lỗi dù file không tồn tại")
	}
}

func TestPerformLocalScan_MissingOscapBinaryReportsErrorNotPanic(t *testing.T) {
	// Môi trường test (golang:alpine) không có oscap — đây chính là hành vi
	// cần đúng khi 1 host trong fleet thiếu package openscap-scanner: báo
	// scan_job_status=error thay vì crash cả Reporter.
	cfg := config{
		scapProfile:    "xccdf_org.ssgproject.content_profile_cis_level1_server",
		scapDatastream: "/nonexistent-datastream.xml",
	}
	summary := performLocalScan(cfg)
	if summary["scan_job_status"] != "error" {
		t.Fatalf("scan_job_status = %v, muốn \"error\" khi thiếu binary oscap", summary["scan_job_status"])
	}
}

func TestPerformLocalScan_TimesOutOnHungOscap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("dùng shell script giả lập oscap treo, chỉ chạy trên Linux (môi trường build/test thật)")
	}
	dir := t.TempDir()
	fakeOscap := filepath.Join(dir, "oscap")
	if err := os.WriteFile(fakeOscap, []byte("#!/bin/sh\nsleep 5\n"), 0755); err != nil {
		t.Fatalf("ghi fake oscap thất bại: %v", err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	cfg := config{
		scapProfile:    "p",
		scapDatastream: "d",
		scanTimeout:    100 * time.Millisecond,
	}
	start := time.Now()
	summary := performLocalScan(cfg)
	elapsed := time.Since(start)

	if summary["scan_job_status"] != "error" {
		t.Fatalf("scan_job_status = %v, muốn \"error\" khi oscap treo quá timeout", summary["scan_job_status"])
	}
	if elapsed > 4*time.Second {
		t.Fatalf("performLocalScan mất %s — timeout không hoạt động (đợi hết sleep 5s thật của fake oscap)", elapsed)
	}
}

func TestTail(t *testing.T) {
	if got := tail("hello", 10); got != "hello" {
		t.Fatalf("tail ngắn hơn n = %q, muốn nguyên văn", got)
	}
	if got := tail("hello world", 5); got != "world" {
		t.Fatalf("tail(11,5) = %q, muốn \"world\"", got)
	}
}
