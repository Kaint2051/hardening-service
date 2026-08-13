package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCpuPercentFromSamples_ComputesUsageFromDelta(t *testing.T) {
	// total tăng 1000 tick, idle tăng 800 -> 20% busy. So sánh có sai số nhỏ
	// (không dùng != trực tiếp) — 800.0/1000.0 không biểu diễn tròn trong
	// float64, kết quả có thể lệch vài ULP so với 20 tuyệt đối.
	got := cpuPercentFromSamples(2000, 10000, 2800, 11000)
	if diffAbs(got, 20) > 0.0001 {
		t.Fatalf("cpuPercentFromSamples = %v, muốn 20", got)
	}
}

func TestCpuPercentFromSamples_NoDeltaReturnsZero(t *testing.T) {
	if got := cpuPercentFromSamples(100, 5000, 100, 5000); got != 0 {
		t.Fatalf("cpuPercentFromSamples không delta = %v, muốn 0", got)
	}
}

func TestCpuPercentFromSamples_TotalWentBackwardsReturnsZero(t *testing.T) {
	// total1 <= total0 không nên xảy ra thật (counter chỉ tăng) nhưng phải
	// an toàn (không panic/không trả số âm) nếu gặp.
	if got := cpuPercentFromSamples(100, 5000, 50, 4000); got != 0 {
		t.Fatalf("cpuPercentFromSamples total lùi = %v, muốn 0", got)
	}
}

func TestRamPercent_ComputesUsedFromAvailable(t *testing.T) {
	// 16GB total, 4GB available -> 75% đang dùng.
	got := ramPercent(16_000_000, 4_000_000)
	if got != 75 {
		t.Fatalf("ramPercent = %v, muốn 75", got)
	}
}

func TestRamPercent_ZeroTotalReturnsZero(t *testing.T) {
	if got := ramPercent(0, 0); got != 0 {
		t.Fatalf("ramPercent(0,0) = %v, muốn 0 (tránh chia 0)", got)
	}
}

func TestRamPercent_AvailableExceedingTotalReturnsZero(t *testing.T) {
	// Không nên xảy ra thật nhưng phải an toàn nếu kernel trả số lạ.
	if got := ramPercent(1000, 2000); got != 0 {
		t.Fatalf("ramPercent với available>total = %v, muốn 0", got)
	}
}

func TestDiskPercentFromStatfs_MatchesDfFormula(t *testing.T) {
	// blocks=100, bfree=30 (còn trống kể cả phần dự trữ root), bavail=25
	// (còn trống với user thường) -> used=70, pct = 70/(70+25) = ~73.68%,
	// KHÔNG PHẢI 70/100=70% (đó là công thức sai, xem comment hàm).
	got := diskPercentFromStatfs(100, 30, 25)
	want := 70.0 / 95.0 * 100
	if diffAbs(got, want) > 0.0001 {
		t.Fatalf("diskPercentFromStatfs = %v, muốn %v", got, want)
	}
}

func TestDiskPercentFromStatfs_FullDiskReturns100(t *testing.T) {
	got := diskPercentFromStatfs(100, 0, 0)
	if got != 100 {
		t.Fatalf("diskPercentFromStatfs đầy ổ = %v, muốn 100", got)
	}
}

func diffAbs(a, b float64) float64 {
	if a > b {
		return a - b
	}
	return b - a
}

func TestReadCPUStat_ParsesAggregateLineNotPerCore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stat")
	// cpu0 phải bị bỏ qua, chỉ đọc dòng "cpu " tổng.
	content := "cpu  100 200 300 4000 500 0 0 0 0 0\ncpu0 10 20 30 400 50 0 0 0 0 0\n"
	os.WriteFile(path, []byte(content), 0600)

	idle, total, err := readCPUStat(path)
	if err != nil {
		t.Fatalf("readCPUStat lỗi: %v", err)
	}
	wantIdle := uint64(4000 + 500) // idle+iowait
	wantTotal := uint64(100 + 200 + 300 + 4000 + 500)
	if idle != wantIdle || total != wantTotal {
		t.Fatalf("readCPUStat = (idle=%d, total=%d), muốn (idle=%d, total=%d)", idle, total, wantIdle, wantTotal)
	}
}

func TestReadCPUStat_MissingFileReturnsError(t *testing.T) {
	if _, _, err := readCPUStat(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatalf("readCPUStat file không tồn tại không lỗi")
	}
}

func TestReadMemInfo_ParsesTotalAndAvailable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meminfo")
	content := "MemTotal:       16384000 kB\nMemFree:         2000000 kB\nMemAvailable:    8000000 kB\n"
	os.WriteFile(path, []byte(content), 0600)

	total, avail, err := readMemInfo(path)
	if err != nil {
		t.Fatalf("readMemInfo lỗi: %v", err)
	}
	if total != 16384000 || avail != 8000000 {
		t.Fatalf("readMemInfo = (%d, %d), muốn (16384000, 8000000)", total, avail)
	}
}

func TestReadMemInfo_MissingAvailableReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meminfo")
	// Kernel rất cũ (<3.14) không có MemAvailable — phải báo lỗi rõ ràng,
	// không âm thầm trả 0.
	os.WriteFile(path, []byte("MemTotal: 1000 kB\nMemFree: 500 kB\n"), 0600)

	if _, _, err := readMemInfo(path); err == nil {
		t.Fatalf("readMemInfo thiếu MemAvailable không lỗi")
	}
}

func TestDefaultRouteInterface_FindsDefaultDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "route")
	content := "Iface\tDestination\tGateway\tFlags\n" +
		"docker0\t000011AC\t00000000\t0001\n" +
		"eth0\t00000000\t0101FE0A\t0003\n"
	os.WriteFile(path, []byte(content), 0600)

	if got := defaultRouteInterface(path); got != "eth0" {
		t.Fatalf("defaultRouteInterface = %q, muốn eth0", got)
	}
}

func TestDefaultRouteInterface_NoDefaultRouteReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "route")
	content := "Iface\tDestination\tGateway\tFlags\n" +
		"docker0\t000011AC\t00000000\t0001\n"
	os.WriteFile(path, []byte(content), 0600)

	if got := defaultRouteInterface(path); got != "" {
		t.Fatalf("defaultRouteInterface không có default route = %q, muốn rỗng", got)
	}
}

func TestFirstNonLoopbackInterface_SkipsLoAndHeaderLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dev")
	content := "Inter-|   Receive\n" +
		" face |bytes    packets\n" +
		"    lo:  100  1  0  0  0  0  0  0  100  1  0  0  0  0  0  0\n" +
		"  eth0: 2000 20  0  0  0  0  0  0 3000 30  0  0  0  0  0  0\n"
	os.WriteFile(path, []byte(content), 0600)

	if got := firstNonLoopbackInterface(path); got != "eth0" {
		t.Fatalf("firstNonLoopbackInterface = %q, muốn eth0", got)
	}
}

func TestPrimaryInterface_FallsBackWhenNoDefaultRoute(t *testing.T) {
	dir := t.TempDir()
	routePath := filepath.Join(dir, "route")
	devPath := filepath.Join(dir, "dev")
	os.WriteFile(routePath, []byte("Iface\tDestination\tGateway\tFlags\n"), 0600)
	os.WriteFile(devPath, []byte(
		"Inter-|   Receive\n face |bytes\n"+
			"    lo:  0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"+
			"  eth0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"), 0600)

	if got := primaryInterface(routePath, devPath); got != "eth0" {
		t.Fatalf("primaryInterface fallback = %q, muốn eth0", got)
	}
}

func TestReadNetDevCounters_ParsesRxAndTxBytesForNamedInterface(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dev")
	content := "Inter-|   Receive\n face |bytes\n" +
		"    lo:  10 0 0 0 0 0 0 0   10 0 0 0 0 0 0 0\n" +
		"  eth0: 2000 20 0 0 0 0 0 0 3000 30 0 0 0 0 0 0\n"
	os.WriteFile(path, []byte(content), 0600)

	rx, tx, err := readNetDevCounters(path, "eth0")
	if err != nil {
		t.Fatalf("readNetDevCounters lỗi: %v", err)
	}
	if rx != 2000 || tx != 3000 {
		t.Fatalf("readNetDevCounters = (rx=%d, tx=%d), muốn (2000, 3000)", rx, tx)
	}
}

func TestReadNetDevCounters_UnknownInterfaceReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dev")
	os.WriteFile(path, []byte("Inter-|   Receive\n face |bytes\n    lo:  0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"), 0600)

	if _, _, err := readNetDevCounters(path, "eth0"); err == nil {
		t.Fatalf("readNetDevCounters interface không tồn tại không lỗi")
	}
}

func TestReadNetDevCounters_EmptyInterfaceNameReturnsError(t *testing.T) {
	if _, _, err := readNetDevCounters("/proc/net/dev", ""); err == nil {
		t.Fatalf("readNetDevCounters với iface rỗng không lỗi")
	}
}

func TestExecutorReachable_TrueWhenListening(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "executor.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("dựng unix socket test thất bại: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	if !executorReachable(socketPath) {
		t.Fatalf("executorReachable = false, muốn true (socket đang lắng nghe)")
	}
}

func TestExecutorReachable_FalseWhenNoListener(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "khong-ai-lang-nghe.sock")
	if executorReachable(socketPath) {
		t.Fatalf("executorReachable = true, muốn false (không có gì lắng nghe)")
	}
}

func TestReadOSPrettyName_ParsesQuotedValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	os.WriteFile(path, []byte("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nID=ubuntu\n"), 0600)

	if got := readOSPrettyName(path); got != "Ubuntu 22.04.4 LTS" {
		t.Fatalf("readOSPrettyName = %q, muốn %q", got, "Ubuntu 22.04.4 LTS")
	}
}

func TestReadOSPrettyName_MissingFileReturnsEmpty(t *testing.T) {
	if got := readOSPrettyName(filepath.Join(t.TempDir(), "missing")); got != "" {
		t.Fatalf("readOSPrettyName file không tồn tại = %q, muốn rỗng", got)
	}
}

func TestReadCPUModel_ParsesModelNameLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cpuinfo")
	content := "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu MHz\t: 2400.0\n"
	os.WriteFile(path, []byte(content), 0600)

	want := "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz"
	if got := readCPUModel(path); got != want {
		t.Fatalf("readCPUModel = %q, muốn %q", got, want)
	}
}

func TestReadUptimeSec_TakesIntegerPartOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uptime")
	os.WriteFile(path, []byte("1306357.07 5427840.75\n"), 0600)

	if got := readUptimeSec(path); got != "1306357" {
		t.Fatalf("readUptimeSec = %q, muốn %q", got, "1306357")
	}
}

func TestFormatGiB_RoundsToOneDecimal(t *testing.T) {
	// 30 GiB chính xác (30 * 1024^3 byte).
	got := formatGiB(30 * 1024 * 1024 * 1024)
	if got != "30.0G" {
		t.Fatalf("formatGiB = %q, muốn %q", got, "30.0G")
	}
}

func TestCollectSystemInfo_ReturnsNonEmptyOnRealMachine(t *testing.T) {
	// Test tích hợp nhẹ — chạy trên máy Linux thật (container CI cũng là
	// Linux) nên /proc/cpuinfo, /proc/uptime... luôn có; chỉ xác nhận có
	// THU THẬP ĐƯỢC gì đó, không assert giá trị cụ thể (khác máy khác giá
	// trị, đó là điều hàm này PHẢI chấp nhận).
	info := collectSystemInfo("/etc/os-release")
	if len(info) == 0 {
		t.Fatalf("collectSystemInfo trả rỗng trên máy Linux thật — ít nhất cpu_cores luôn có (runtime.NumCPU())")
	}
	if _, ok := info["cpu_cores"]; !ok {
		t.Fatalf("collectSystemInfo thiếu cpu_cores — field này KHÔNG PHỤ THUỘC file/binary ngoài (runtime.NumCPU())")
	}
}
