package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"
)

// generateTestCertPEM sinh 1 cert self-signed ECDSA P256 với NotBefore/
// NotAfter và CommonName tuỳ ý — dùng cho cả test certHolder (cần cert có
// mốc hiệu lực biết trước để kiểm renewalDeadline) lẫn test renewCert (cần
// PEM thật để tls.X509KeyPair parse được qua 1 server test giả lập Agent
// Manager). Theo đúng cách generateSelfSignedPEM ở
// apps/agent-manager/main_test.go đã làm cho mục đích tương tự — không tự
// chế crypto, dùng thẳng crypto/x509 thật.
func generateTestCertPEM(t *testing.T, commonName string, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("sinh key test thất bại: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("tạo cert test thất bại: %v", err)
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key test thất bại: %v", err)
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certOut), string(keyOut)
}

// generateTestCert giống generateTestCertPEM nhưng trả thẳng tls.Certificate
// đã parse — dùng cho test certHolder.set()/get()/leaf(), vốn thao tác trực
// tiếp trên kiểu tls.Certificate chứ không phải chuỗi PEM.
func generateTestCert(t *testing.T, commonName string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	certPEM, keyPEM := generateTestCertPEM(t, commonName, notBefore, notAfter)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("X509KeyPair cho cert test thất bại: %v", err)
	}
	return cert
}

func TestCertHolder_SetThenGetReturnsSameCert(t *testing.T) {
	h := &certHolder{}
	cert := generateTestCert(t, "agent-a", time.Now(), time.Now().Add(time.Hour))
	h.set(cert)

	got, err := h.get(nil)
	if err != nil {
		t.Fatalf("get() lỗi: %v", err)
	}
	if len(got.Certificate) == 0 || string(got.Certificate[0]) != string(cert.Certificate[0]) {
		t.Fatalf("get() trả cert khác với cert đã set()")
	}
}

func TestCertHolder_SetHotSwapsSubsequentGet(t *testing.T) {
	h := &certHolder{}
	oldCert := generateTestCert(t, "agent-old", time.Now(), time.Now().Add(time.Hour))
	newCert := generateTestCert(t, "agent-new", time.Now(), time.Now().Add(2*time.Hour))

	h.set(oldCert)
	got1, err := h.get(nil)
	if err != nil {
		t.Fatalf("get() lỗi trước khi renew: %v", err)
	}
	if string(got1.Certificate[0]) != string(oldCert.Certificate[0]) {
		t.Fatalf("get() trước khi set() cert mới phải trả cert CŨ")
	}

	h.set(newCert)
	got2, err := h.get(nil)
	if err != nil {
		t.Fatalf("get() lỗi sau khi renew: %v", err)
	}
	if string(got2.Certificate[0]) != string(newCert.Certificate[0]) {
		t.Fatalf("get() SAU khi set() cert mới vẫn trả cert CŨ — hot-swap không hoạt động")
	}
}

func TestCertHolder_LeafOnEmptyHolderReturnsError(t *testing.T) {
	h := &certHolder{}
	if _, err := h.leaf(); err == nil {
		t.Fatalf("leaf() không lỗi dù certHolder chưa từng set() — phải báo lỗi rõ ràng thay vì panic hay trả cert rỗng")
	}
}

func TestCertHolder_LeafParsesCurrentCertValidity(t *testing.T) {
	notBefore := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)
	cert := generateTestCert(t, "agent-a", notBefore, notAfter)

	h := &certHolder{}
	h.set(cert)

	leaf, err := h.leaf()
	if err != nil {
		t.Fatalf("leaf() lỗi: %v", err)
	}
	if !leaf.NotBefore.Equal(notBefore) || !leaf.NotAfter.Equal(notAfter) {
		t.Fatalf("leaf() NotBefore/NotAfter = %s/%s, muốn %s/%s", leaf.NotBefore, leaf.NotAfter, notBefore, notAfter)
	}
}

func TestCertHolder_LeafReflectsCertAfterHotSwap(t *testing.T) {
	oldNotAfter := time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)
	newNotAfter := time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC)
	oldCert := generateTestCert(t, "agent-old", time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), oldNotAfter)
	newCert := generateTestCert(t, "agent-new", time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), newNotAfter)

	h := &certHolder{}
	h.set(oldCert)
	h.set(newCert)

	leaf, err := h.leaf()
	if err != nil {
		t.Fatalf("leaf() lỗi: %v", err)
	}
	if !leaf.NotAfter.Equal(newNotAfter) {
		t.Fatalf("leaf() sau hot-swap vẫn phản ánh cert CŨ (NotAfter=%s), muốn cert MỚI (NotAfter=%s) — runRenewalLoop sẽ tính sai hạn renew tiếp theo", leaf.NotAfter, newNotAfter)
	}
}

// TestCertHolder_ConcurrentGetSetIsRaceSafe chạy song song rất nhiều lần
// get()/set() để bắt lỗi truy cập không đồng bộ vào field `cert` nội bộ.
// Giá trị lớn nhất của test này có được khi chạy với `go test -race` (không
// chạy được trong sandbox review này — không có Go toolchain, xem ghi chú ở
// cuối); tự thân test vẫn có ý nghĩa: nếu certHolder khoá sai (vd lỡ tay đảo
// RLock/Lock, hoặc quên khoá 1 nhánh), get() có thể trả về 1 cert "lai" —
// Certificate (DER) của 1 cert trộn PrivateKey của cert khác — hoặc panic do
// đọc/ghi đồng thời trên cùng slice; test dưới đây khẳng định MỌI kết quả
// get() phải khớp NGUYÊN VẸN với 1 trong các cert đã set(), không lai tạp.
func TestCertHolder_ConcurrentGetSetIsRaceSafe(t *testing.T) {
	h := &certHolder{}
	certA := generateTestCert(t, "agent-a", time.Now(), time.Now().Add(time.Hour))
	certB := generateTestCert(t, "agent-b", time.Now(), time.Now().Add(time.Hour))
	h.set(certA)

	knownRaw := map[string]bool{
		string(certA.Certificate[0]): true,
		string(certB.Certificate[0]): true,
	}

	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(2)

	// 2 writer song song, luân phiên set() 2 cert khác nhau.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			h.set(certA)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			h.set(certB)
		}
	}()

	// Reader chạy trên chính goroutine test — được phép gọi t.Fatalf trực
	// tiếp (không giống handler chạy trên goroutine riêng của httptest).
	for i := 0; i < iterations; i++ {
		got, err := h.get(nil)
		if err != nil {
			t.Fatalf("get() lỗi giữa lúc đang có set() đồng thời: %v", err)
		}
		if len(got.Certificate) == 0 || !knownRaw[string(got.Certificate[0])] {
			t.Fatalf("get() trả cert không khớp bất kỳ cert nào đã set() — nghi ngờ đọc không đồng bộ/dữ liệu rách")
		}
	}
	wg.Wait()
}

// TestCertHolder_ConcurrentLeafDuringSetIsRaceSafe tương tự test trên nhưng
// cho leaf() — runRenewalLoop gọi leaf() đồng thời với lúc renewCert (chạy ở
// goroutine renewal riêng) có thể đang set() cert mới; leaf() không được
// panic hay trả về NotBefore/NotAfter của 2 cert trộn lẫn.
func TestCertHolder_ConcurrentLeafDuringSetIsRaceSafe(t *testing.T) {
	h := &certHolder{}
	notAfterA := time.Now().Add(time.Hour)
	notAfterB := time.Now().Add(2 * time.Hour)
	certA := generateTestCert(t, "agent-a", time.Now(), notAfterA)
	certB := generateTestCert(t, "agent-b", time.Now(), notAfterB)
	h.set(certA)

	knownNotAfter := map[int64]bool{
		notAfterA.Unix(): true,
		notAfterB.Unix(): true,
	}

	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if i%2 == 0 {
				h.set(certA)
			} else {
				h.set(certB)
			}
		}
	}()

	for i := 0; i < iterations; i++ {
		leaf, err := h.leaf()
		if err != nil {
			t.Fatalf("leaf() lỗi giữa lúc đang có set() đồng thời: %v", err)
		}
		if !knownNotAfter[leaf.NotAfter.Unix()] {
			t.Fatalf("leaf() trả NotAfter=%s không khớp cert A (%s) lẫn cert B (%s) — nghi ngờ đọc rách", leaf.NotAfter, notAfterA, notAfterB)
		}
	}
	wg.Wait()
}
