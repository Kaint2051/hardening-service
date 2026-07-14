package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

func loadCertPool(rootPath string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, fmt.Errorf("đọc CA root tại %s thất bại (operator phải đặt file này trước khi chạy agent): %w", rootPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("CA root tại %s không phải PEM hợp lệ", rootPath)
	}
	return pool, nil
}

// buildEnrollClient verify server (Agent Manager) bằng root CA đã có sẵn,
// KHÔNG gửi client cert (agent chưa có) — dùng đúng 1 lần cho /enroll.
// serverName phải khớp subject step-ca đã ký cho cert của Agent Manager
// (mint_agent_manager_server_cert ở Orchestrator), vì managerURL thường là
// địa chỉ IP/host thật (vd 172.30.2.111), không khớp SAN trong cert.
func buildEnrollClient(rootPath, serverName string) (*http.Client, error) {
	pool, err := loadCertPool(rootPath)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: serverName,
			},
		},
	}, nil
}

// certHolder giữ cert/key mTLS hiện hành của agent trong bộ nhớ, cho phép
// renewCert (main.go) hot-swap cert mới vào client HTTP đang chạy mà không
// cần khởi động lại process — mirror serverIdentity ở
// apps/agent-manager/main.go, nhưng phía CLIENT dùng tls.Config.
// GetClientCertificate (callback per-handshake) thay vì GetConfigForClient
// (chỉ có ở phía server).
type certHolder struct {
	mu   sync.RWMutex
	cert tls.Certificate
}

// get khớp chữ ký tls.Config.GetClientCertificate — trả bản sao cert hiện
// hành tại thời điểm handshake, không phải con trỏ trực tiếp vào field nội
// bộ, để lock không bị giữ ngoài phạm vi hàm này.
func (h *certHolder) get(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	cert := h.cert
	return &cert, nil
}

// set hot-swap cert mới — gọi sau khi renewCert đã validate + ghi file
// thành công, để mọi request SAU thời điểm này (kể cả đang có sẵn) dùng
// ngay cert mới ở lần handshake tiếp theo.
func (h *certHolder) set(cert tls.Certificate) {
	h.mu.Lock()
	h.cert = cert
	h.mu.Unlock()
}

// leaf parse lại leaf cert (DER đầu tiên) hiện hành thành *x509.Certificate
// để renewalLoop (main.go) đọc NotBefore/NotAfter tính mốc renew tiếp theo —
// không cache *x509.Certificate song song với tls.Certificate để tránh 2
// nguồn sự thật lệch nhau sau mỗi lần set().
func (h *certHolder) leaf() (*x509.Certificate, error) {
	h.mu.RLock()
	raw := h.cert.Certificate
	h.mu.RUnlock()
	if len(raw) == 0 {
		return nil, fmt.Errorf("certHolder chưa có cert nào được nạp")
	}
	return x509.ParseCertificate(raw[0])
}

// buildMTLSClient dùng cho mọi request SAU enroll (heartbeat, scan-result,
// fim-event, renew) — verify server VÀ trình client cert thật. Cert được
// nạp qua GetClientCertificate (không phải Certificates tĩnh) để
// certHolder.set() ở renewCert (main.go) hot-swap được cert mới, không cần
// dựng lại http.Client/Transport hay restart process.
func buildMTLSClient(certPath, keyPath, rootPath, serverName string) (*http.Client, *certHolder, error) {
	pool, err := loadCertPool(rootPath)
	if err != nil {
		return nil, nil, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("đọc cert/key agent tại %s/%s thất bại: %w", certPath, keyPath, err)
	}
	holder := &certHolder{}
	holder.set(cert)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:              pool,
				GetClientCertificate: holder.get,
				ServerName:           serverName,
			},
		},
	}
	return client, holder, nil
}
