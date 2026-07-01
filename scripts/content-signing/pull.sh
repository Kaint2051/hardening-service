#!/usr/bin/env bash
# Vai trò: PULLER — tải nội dung gốc (benchmark/CVE feed) về khu cách ly.
# Không được ký nội dung ở bước này ngoài việc ký MANIFEST bằng chính GPG key
# cá nhân của Puller, để có bằng chứng mật mã học "ai là người tải".
#
# Dùng: ./pull.sh <source_url> <name>
set -euo pipefail

SOURCE_URL="${1:?thiếu source_url}"
NAME="${2:?thiếu name (vd: complianceascode-v0.1.73)}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DIR="${ROOT_DIR}/staging/${NAME}-${STAMP}"
mkdir -p "$DIR"

echo "==> [PULLER] Tải nội dung từ: ${SOURCE_URL}"
curl -fsSL "$SOURCE_URL" -o "$DIR/content.tar.gz"

SHA256=$(sha256sum "$DIR/content.tar.gz" | awk '{print $1}')

cat > "$DIR/manifest.json" <<EOF
{
  "name": "${NAME}",
  "source_url": "${SOURCE_URL}",
  "pulled_by": "$(git config user.email 2>/dev/null || whoami)",
  "pulled_at": "${STAMP}",
  "sha256": "${SHA256}"
}
EOF

echo "==> [PULLER] Ký manifest.json bằng GPG key cá nhân (chứng minh danh tính người tải)"
gpg --clearsign --output "$DIR/manifest.json.asc" "$DIR/manifest.json"

echo ""
echo "==> Xong: $DIR"
echo "    Bước tiếp theo: một REVIEWER KHÁC (GPG key khác) chạy review.sh trên thư mục này."
