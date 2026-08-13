import type { Finding } from "../api/types";

// Phân nhóm finding theo CHỦ ĐỀ để bảng 180+ dòng còn xử lý được (mục "list
// ra hết nó khó xử lý").
//
// Suy từ `rule_id` chứ không phải từ dữ liệu chuẩn: XCCDF có sẵn cây <Group>
// mô tả đúng chủ đề, NHƯNG group đó nằm trong benchmark/datastream, không
// nằm trong file kết quả mà scan.sh parse (chỉ có <rule-result idref=...>).
// Lấy group thật sẽ phải parse thêm cả datastream ~100MB trong container
// scan rồi kèm vào từng finding — chi phí lớn cho 1 việc thuần hiển thị.
// Quy ước đặt tên rule_id của ComplianceAsCode đủ nhất quán để nhóm chính
// xác, và nhóm "Khác" hứng mọi rule không khớp nên không bao giờ mất dòng.
//
// THỨ TỰ QUAN TRỌNG: khớp từ cụ thể tới chung, lấy nhóm ĐẦU TIÊN khớp. Vd
// `file_permissions_sshd_config` phải vào nhóm SSH chứ không phải "Quyền
// file", `package_aide_installed` vào AIDE chứ không phải "Gói & dịch vụ".
// Đổi thứ tự = đổi kết quả phân nhóm.
interface CategoryDef {
  key: string;
  label: string;
  match: RegExp;
}

const CATEGORY_DEFS: CategoryDef[] = [
  { key: "aide", label: "Giám sát toàn vẹn tệp (AIDE)", match: /aide/ },
  {
    key: "ssh",
    label: "SSH",
    match: /sshd|ssh_config|disable_host_auth/,
  },
  { key: "cron", label: "Tác vụ định kỳ (cron/at)", match: /cron|crontab|at_allow/ },
  { key: "boot", label: "Khởi động (GRUB)", match: /grub2/ },
  { key: "logging", label: "Nhật ký hệ thống", match: /rsyslog|syslog|journald|logrotate/ },
  { key: "firewall", label: "Tường lửa", match: /iptables|firewalld|ufw|nftables/ },
  { key: "time", label: "Đồng bộ thời gian", match: /chrony|ntp|timesync/ },
  {
    key: "sysctl",
    label: "Tham số kernel & mạng (sysctl)",
    match: /^sysctl_|wireless/,
  },
  {
    key: "fs",
    label: "Hệ thống tệp & phân vùng",
    match: /^kernel_module_|^mount_option_|^partition_for_/,
  },
  {
    key: "accounts",
    label: "Tài khoản & mật khẩu",
    match: /^account|^no_empty_passwords|^no_netrc|^no_shelllogin|use_pam_wheel/,
  },
  {
    key: "services",
    label: "Gói & dịch vụ không cần thiết",
    match: /^package_|^service_|rsh_trust/,
  },
  {
    key: "permissions",
    label: "Quyền & sở hữu tệp",
    match: /^file_owner|^file_groupowner|^file_permissions|^dir_perms|no_files_unowned/,
  },
];

const OTHER: CategoryDef = { key: "other", label: "Khác", match: /.^/ };

// rule_id thật có tiền tố XCCDF dài ("xccdf_org.ssgproject.content_rule_...")
// — bỏ đi trước khi khớp để regex neo đầu chuỗi (^) hoạt động đúng.
const RULE_ID_PREFIX = "xccdf_org.ssgproject.content_rule_";

export function shortRuleId(ruleId: string): string {
  return ruleId.startsWith(RULE_ID_PREFIX) ? ruleId.slice(RULE_ID_PREFIX.length) : ruleId;
}

export function categoryOf(ruleId: string): CategoryDef {
  const short = shortRuleId(ruleId);
  return CATEGORY_DEFS.find((c) => c.match.test(short)) ?? OTHER;
}

export interface FindingGroup {
  key: string;
  label: string;
  findings: Finding[];
  failCount: number;
  passCount: number;
}

/**
 * Gom findings thành các nhóm chủ đề, sắp xếp NHÓM NHIỀU LỖI LÊN TRƯỚC (việc
 * cần xử lý nổi lên trên; nhóm đã sạch lỗi trôi xuống cuối). Nhóm rỗng bị bỏ
 * hẳn — không hiển thị chủ đề mà bản quét này không có rule nào.
 */
export function groupFindings(findings: Finding[]): FindingGroup[] {
  const byKey = new Map<string, FindingGroup>();
  for (const f of findings) {
    const cat = categoryOf(f.rule_id);
    let group = byKey.get(cat.key);
    if (!group) {
      group = { key: cat.key, label: cat.label, findings: [], failCount: 0, passCount: 0 };
      byKey.set(cat.key, group);
    }
    group.findings.push(f);
    if (f.result === "fail") group.failCount += 1;
    else group.passCount += 1;
  }
  return [...byKey.values()].sort(
    (a, b) => b.failCount - a.failCount || a.label.localeCompare(b.label, "vi")
  );
}
