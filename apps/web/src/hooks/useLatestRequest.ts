import { useCallback, useRef } from "react";

// Tổng quát hoá race-guard vốn viết tay ở HostsPage/JobsPage (enrollRequestIdRef,
// detailRequestIdRef...). Mỗi lần bắt đầu 1 thao tác async, gọi begin() để lấy
// 1 mốc tăng dần; khi promise resolve gọi isStale() — nếu đã có thao tác mới
// hơn bắt đầu sau đó thì bỏ kết quả cũ, không đè state bằng dữ liệu lỗi thời
// (vd đổi host giữa lúc quét, mở nhanh 2 dialog chi tiết liên tiếp).
//
// Dùng: const beginScan = useLatestRequest();  // 1 lần / 1 thao tác độc lập
//        const isStale = beginScan();
//        const data = await api...();
//        if (isStale()) return;                 // bỏ qua nếu đã cũ
export function useLatestRequest(): () => () => boolean {
  const ref = useRef(0);
  return useCallback(() => {
    const id = ++ref.current;
    return () => ref.current !== id;
  }, []);
}
