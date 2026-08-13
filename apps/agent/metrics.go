// Thu thập số liệu tài nguyên máy (CPU/RAM/Disk %, interface mạng chính +
// % băng thông so với tốc độ link) và báo lên Agent Manager mỗi
// cfg.metricsInterval — ĐỘC LẬP với heartbeat (cadence khác nhau, mặc định
// 3 phút so với 60s) vì cần 1 khoảng sleep ngắn để lấy delta CPU/network,
// không muốn làm heartbeat (tín hiệu "còn sống") bị trễ theo nó. CHỈ đọc
// /proc, /sys bằng thư viện chuẩn — không thêm dependency ngoài (gopsutil...),
// giữ đúng triết lý Reporter quyền tối thiểu/build tĩnh không phụ thuộc.
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// metricsSampleGap là khoảng chờ giữa 2 lần đọc /proc/stat + /proc/net/dev
// để tính delta CPU%/network throughput — dùng CHUNG 1 lần sleep cho cả 2
// (không sleep riêng từng cái). Đủ ngắn để không làm chậm đáng kể vòng lặp
// (cadence mặc định đã là 3 phút), đủ dài để không bị nhiễu bởi 1 tick lệch.
const metricsSampleGap = 1 * time.Second

const (
	procStatPath  = "/proc/stat"
	procMemPath   = "/proc/meminfo"
	procRoutePath = "/proc/net/route"
	procDevPath   = "/proc/net/dev"
)

type hostMetrics struct {
	cpuPct   float64
	ramPct   float64
	diskPct  float64
	netIface string
	netPct   *float64
}

func runMetricsLoop(client *http.Client, cfg config) {
	log.Printf("bắt đầu vòng lặp metrics mỗi %s tới %s", cfg.metricsInterval, cfg.managerURL)
	for {
		runProtected("metrics", func() { runMetricsOnce(client, cfg) })
		time.Sleep(cfg.metricsInterval)
	}
}

func runMetricsOnce(client *http.Client, cfg config) {
	m, err := collectMetrics()
	if err != nil {
		log.Printf("thu thập metrics lỗi: %v", err)
		return
	}
	body := map[string]any{
		"hostname": cfg.hostname,
		"cpu_pct":  m.cpuPct,
		"ram_pct":  m.ramPct,
		"disk_pct": m.diskPct,
		// executor_reachable — CHỈ connect-rồi-đóng ngay, KHÔNG gửi job
		// envelope thật (tránh vô tình kích hoạt Executor xử lý 1 "job" rỗng/
		// lạ) — tín hiệu chủ động để UI biết Executor chết TRƯỚC KHI ai đó
		// thử remediate thật rồi mới phát hiện qua lỗi khó hiểu (phát hiện qua
		// rà soát đối kháng: trước bản này KHÔNG có gì dial socket này ngoài
		// lúc dispatch 1 job thật, xem remediate.go:executeViaExecutor).
		"executor_reachable": executorReachable(cfg.executorSocketPath),
	}
	// net_iface/net_pct bỏ HẲN key thay vì gửi rỗng/null khi không xác định
	// được — cùng quy ước os_family/os_version ở heartbeat() (main.go).
	if m.netIface != "" {
		body["net_iface"] = m.netIface
	}
	if m.netPct != nil {
		body["net_pct"] = *m.netPct
	}
	// system_info — OS/kernel/CPU/RAM tổng/ổ đĩa, y hệt field ssh-check.sh
	// thu qua SSH (app/models.py:Host.system_info) nhưng đọc trực tiếp tại
	// chỗ — Agent đã chạy sẵn trên máy, không cần round-trip SSH nữa. Ghi
	// vào ĐÚNG cột đó nên host quản lý HOÀN TOÀN qua Agent (chưa từng "Test
	// SSH") vẫn thấy đầy đủ "Thông tin máy" ở UI, không cần đổi gì phía đó.
	if info := collectSystemInfo(cfg.osReleasePath); len(info) > 0 {
		body["system_info"] = info
	}
	if err := postAndExpect(client, cfg.managerURL+"/host-metrics", body, http.StatusNoContent); err != nil {
		log.Printf("gửi metrics report lỗi: %v", err)
		return
	}
	netPctLog := "N/A"
	if m.netPct != nil {
		netPctLog = fmt.Sprintf("%.1f%%", *m.netPct)
	}
	log.Printf("metrics report OK: cpu=%.1f%% ram=%.1f%% disk=%.1f%% net_iface=%q net_pct=%s executor_reachable=%v",
		m.cpuPct, m.ramPct, m.diskPct, m.netIface, netPctLog, body["executor_reachable"])
}

// executorReachable dial-rồi-đóng NGAY Unix socket của Executor — chỉ để
// biết "có gì đang lắng nghe ở đó không", KHÔNG gửi/đọc bất kỳ jobEnvelope
// nào (khác executeViaExecutor ở remediate.go, dùng khi THẬT SỰ có job).
func executorReachable(socketPath string) bool {
	conn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// collectSystemInfo đọc lại ĐÚNG các field ssh-check.sh thu qua SSH
// (_SSH_CHECK_SYSTEM_KEYS phía Orchestrator) nhưng bằng cách đọc trực tiếp
// trên máy — mỗi field đọc lỗi CHỈ bỏ field đó (map thiếu key), không bỏ cả
// lần báo cáo, cùng triết lý "máy thiếu 1 file/tool không được làm cả job
// fail" của ssh-check.sh.
func collectSystemInfo(osReleasePath string) map[string]string {
	info := map[string]string{}
	if v := readOSPrettyName(osReleasePath); v != "" {
		info["os_pretty"] = v
	}
	if v := runCommandTrimmed("uname", "-r"); v != "" {
		info["kernel"] = v
	}
	if v := runCommandTrimmed("uname", "-m"); v != "" {
		info["arch"] = v
	}
	if v := readCPUModel("/proc/cpuinfo"); v != "" {
		info["cpu_model"] = v
	}
	info["cpu_cores"] = strconv.Itoa(runtime.NumCPU())
	if totalKB, _, err := readMemInfo(procMemPath); err == nil {
		info["mem_total_kb"] = strconv.FormatUint(totalKB, 10)
	}
	if blocks, _, bavail, bsize, err := statfsRoot(); err == nil {
		info["disk_root"] = formatGiB(blocks*bsize) + "/" + formatGiB(bavail*bsize)
	}
	if v := detectVirt(); v != "" {
		info["virt"] = v
	}
	if v := readUptimeSec("/proc/uptime"); v != "" {
		info["uptime_sec"] = v
	}
	return info
}

func readOSPrettyName(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if key == "PRETTY_NAME" {
			return strings.Trim(val, `"`)
		}
	}
	return ""
}

func readCPUModel(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			_, val, ok := strings.Cut(line, ":")
			if ok {
				return strings.TrimSpace(val)
			}
		}
	}
	return ""
}

func readUptimeSec(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return ""
	}
	return strings.SplitN(fields[0], ".", 2)[0]
}

// detectVirt chạy `systemd-detect-virt` — binary này CỐ Ý exit code 1 (không
// phải lỗi) khi không phát hiện ảo hoá, vẫn in "none" ra stdout, nên vẫn
// dùng output kể cả khi err là *exec.ExitError; chỉ coi là "không đọc được"
// (trả "") khi lỗi KHÁC (thiếu binary...).
func detectVirt() string {
	out, err := exec.Command("systemd-detect-virt").Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return ""
		}
	}
	return strings.TrimSpace(string(out))
}

func runCommandTrimmed(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// formatGiB đổi byte sang chuỗi "<so>G" (1 chữ số thập phân) — khớp cách
// SYSTEM_INFO_ROWS.disk_root.format phía frontend (HostsPage.tsx) ghép chuỗi
// "<tổng>/<còn trống>" sẵn có từ ssh-check.sh (`df -h`), không cần đổi gì UI.
func formatGiB(bytes uint64) string {
	gib := float64(bytes) / (1024 * 1024 * 1024)
	return fmt.Sprintf("%.1fG", gib)
}

// collectMetrics lấy CPU/RAM/Disk/Network trong CÙNG 1 khoảng sleep
// (metricsSampleGap) — CPU và network đều cần 2 mốc thời gian để tính
// delta. CPU/RAM/Disk là field BẮT BUỘC ở AgentMetricsRequest phía
// Orchestrator (app/schemas.py) — đọc lỗi bất kỳ cái nào trong 3 cái đó thì
// bỏ HẲN lần báo cáo này (không gửi số giả 0), khác Network (field TUỲ
// CHỌN — interface không xác định được/tốc độ link không đọc được là tình
// huống BÌNH THƯỜNG, đặc biệt trên máy ảo virtio-net, không được coi là lỗi
// chặn cả lần báo cáo).
func collectMetrics() (hostMetrics, error) {
	idle0, total0, err := readCPUStat(procStatPath)
	if err != nil {
		return hostMetrics{}, fmt.Errorf("đọc %s lần 1: %w", procStatPath, err)
	}
	iface := primaryInterface(procRoutePath, procDevPath)
	rx0, tx0, netErr0 := readNetDevCounters(procDevPath, iface)
	t0 := time.Now()

	time.Sleep(metricsSampleGap)

	idle1, total1, err := readCPUStat(procStatPath)
	if err != nil {
		return hostMetrics{}, fmt.Errorf("đọc %s lần 2: %w", procStatPath, err)
	}
	rx1, tx1, netErr1 := readNetDevCounters(procDevPath, iface)
	elapsed := time.Since(t0)

	ramTotal, ramAvail, err := readMemInfo(procMemPath)
	if err != nil {
		return hostMetrics{}, fmt.Errorf("đọc %s: %w", procMemPath, err)
	}
	blocks, bfree, bavail, _, err := statfsRoot()
	if err != nil {
		return hostMetrics{}, fmt.Errorf("statfs /: %w", err)
	}

	m := hostMetrics{
		cpuPct:   cpuPercentFromSamples(idle0, total0, idle1, total1),
		ramPct:   ramPercent(ramTotal, ramAvail),
		diskPct:  diskPercentFromStatfs(blocks, bfree, bavail),
		netIface: iface,
	}
	if netErr0 == nil && netErr1 == nil && iface != "" && elapsed > 0 {
		bytesDelta := (rx1 + tx1) - (rx0 + tx0)
		bitsPerSec := float64(bytesDelta) * 8 / elapsed.Seconds()
		if speedMbps, speedErr := readNetSpeedMbps(iface); speedErr == nil && speedMbps > 0 {
			pct := bitsPerSec / (float64(speedMbps) * 1e6) * 100
			if pct > 100 {
				pct = 100
			}
			m.netPct = &pct
		}
		// speedErr != nil hoặc speedMbps <= 0 (rất phổ biến trên NIC virtio
		// của máy ảo — /sys/class/net/<iface>/speed trả lỗi hoặc -1): net_pct
		// ở lại nil, net_iface vẫn báo — UI phân biệt "biết card nào" khác
		// "không đọc được tốc độ link của card đó".
	}
	return m, nil
}

// cpuPercentFromSamples tính %CPU đang dùng từ 2 mốc /proc/stat — idle đã
// gồm cả iowait (chờ I/O không tính là "đang tính toán"), total là tổng mọi
// field của dòng "cpu " tổng (user+nice+system+idle+iowait+irq+softirq+...).
func cpuPercentFromSamples(idle0, total0, idle1, total1 uint64) float64 {
	if total1 <= total0 {
		return 0
	}
	deltaTotal := total1 - total0
	// idle1 < idle0 không nên xảy ra (idle chỉ tăng) nhưng vẫn phòng counter
	// lạ (vd hệ thống chỉnh giờ/hibernate) — coi như 0% busy thay vì âm.
	if idle1 < idle0 {
		return 0
	}
	deltaIdle := idle1 - idle0
	pct := (1 - float64(deltaIdle)/float64(deltaTotal)) * 100
	return clampPercent(pct)
}

// ramPercent = (Total-Available)/Total*100 — dùng MemAvailable (đúng nghĩa
// "còn dùng được", đã tính cả cache có thể giải phóng), KHÔNG dùng MemFree
// (chỉ đếm phần chưa từng đụng tới, luôn thấp hơn thực tế rất nhiều trên
// Linux vì page cache).
func ramPercent(totalKB, availKB uint64) float64 {
	if totalKB == 0 || availKB > totalKB {
		return 0
	}
	pct := float64(totalKB-availKB) / float64(totalKB) * 100
	return clampPercent(pct)
}

// diskPercentFromStatfs dùng ĐÚNG công thức `df` (used/(used+avail)*100,
// KHÔNG PHẢI used/blocks*100) để khớp số % người dùng quen thấy từ `df -h` —
// ext4 dành ra ~5% block cho root, `df` trừ phần đó khỏi mẫu số.
func diskPercentFromStatfs(blocks, bfree, bavail uint64) float64 {
	if blocks < bfree {
		return 0
	}
	used := blocks - bfree
	denom := used + bavail
	if denom == 0 {
		return 0
	}
	pct := float64(used) / float64(denom) * 100
	return clampPercent(pct)
}

func clampPercent(pct float64) float64 {
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return pct
}

// readCPUStat đọc dòng "cpu " TỔNG (không phải "cpu0"/"cpu1"...) của
// /proc/stat — trả (idle+iowait, tổng mọi field) để cpuPercentFromSamples
// tính delta.
func readCPUStat(path string) (idle, total uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// fields[0] phải là ĐÚNG "cpu" (dòng tổng) — "cpu0"/"cpu1" là per-core,
		// bỏ qua.
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var sum uint64
		for _, s := range fields[1:] {
			v, convErr := strconv.ParseUint(s, 10, 64)
			if convErr != nil {
				break
			}
			sum += v
		}
		idleVal, idleErr := strconv.ParseUint(fields[4], 10, 64)
		if idleErr != nil {
			return 0, 0, fmt.Errorf("parse field idle (cpu) lỗi: %w", idleErr)
		}
		var iowaitVal uint64
		if len(fields) > 5 {
			iowaitVal, _ = strconv.ParseUint(fields[5], 10, 64)
		}
		return idleVal + iowaitVal, sum, nil
	}
	return 0, 0, fmt.Errorf("không thấy dòng 'cpu' tổng trong %s", path)
}

// readMemInfo đọc MemTotal/MemAvailable (đơn vị kB) từ /proc/meminfo.
func readMemInfo(path string) (totalKB, availKB uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	var haveTotal, haveAvail bool
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			if totalKB, err = parseMeminfoValue(line); err != nil {
				return 0, 0, err
			}
			haveTotal = true
		case strings.HasPrefix(line, "MemAvailable:"):
			if availKB, err = parseMeminfoValue(line); err != nil {
				return 0, 0, err
			}
			haveAvail = true
		}
		if haveTotal && haveAvail {
			break
		}
	}
	if !haveTotal || !haveAvail {
		return 0, 0, fmt.Errorf("thiếu MemTotal/MemAvailable trong %s", path)
	}
	return totalKB, availKB, nil
}

func parseMeminfoValue(line string) (uint64, error) {
	fields := strings.Fields(line) // vd ["MemTotal:", "16384000", "kB"]
	if len(fields) < 2 {
		return 0, fmt.Errorf("dòng meminfo không hợp lệ: %q", line)
	}
	return strconv.ParseUint(fields[1], 10, 64)
}

// statfsRoot trả thêm bsize (byte/block) so với bản đầu — diskPercentFromStatfs
// chỉ cần TỈ LỆ (bsize tự triệt tiêu) nhưng collectSystemInfo cần quy đổi
// blocks/bavail sang byte THẬT để hiển thị "disk_root" (GiB), nên phải giữ
// lại giá trị này ở đây thay vì bỏ qua như bản đầu.
func statfsRoot() (blocks, bfree, bavail, bsize uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, 0, 0, 0, err
	}
	return uint64(st.Blocks), uint64(st.Bfree), uint64(st.Bavail), uint64(st.Bsize), nil
}

// primaryInterface chọn interface mạng "chính" để đo % băng thông: ưu tiên
// interface của default route (/proc/net/route, cột Destination=00000000),
// fallback interface non-loopback ĐẦU TIÊN thấy trong /proc/net/dev nếu
// không tìm được default route (hiếm trên server, vd network namespace lạ).
func primaryInterface(routePath, devPath string) string {
	if iface := defaultRouteInterface(routePath); iface != "" {
		return iface
	}
	return firstNonLoopbackInterface(devPath)
}

func defaultRouteInterface(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	firstLine := true
	for scanner.Scan() {
		if firstLine {
			firstLine = false
			continue // header: "Iface Destination Gateway Flags ..."
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

func firstNonLoopbackInterface(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue // 2 dòng header cố định của /proc/net/dev
		}
		line := scanner.Text()
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		if name != "" && name != "lo" {
			return name
		}
	}
	return ""
}

// readNetDevCounters đọc rx_bytes (field đầu sau ":") + tx_bytes (field thứ
// 9 sau ":" — 8 field rx rồi tới 8 field tx, xem format /proc/net/dev) cho
// ĐÚNG 1 interface.
func readNetDevCounters(path, iface string) (rx, tx uint64, err error) {
	if iface == "" {
		return 0, 0, fmt.Errorf("chưa xác định được interface")
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		if name != iface {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 9 {
			return 0, 0, fmt.Errorf("dòng /proc/net/dev cho %s thiếu field", iface)
		}
		rxBytes, err1 := strconv.ParseUint(fields[0], 10, 64)
		txBytes, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("parse counters %s lỗi", iface)
		}
		return rxBytes, txBytes, nil
	}
	return 0, 0, fmt.Errorf("không thấy interface %s trong %s", iface, path)
}

// readNetSpeedMbps đọc tốc độ link (Mbps) — THƯỜNG lỗi/trả giá trị âm trên
// NIC virtio-net của máy ảo (không phải bug, xem comment collectMetrics).
func readNetSpeedMbps(iface string) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/speed", iface))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}
