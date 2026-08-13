import { ApiError } from "../api/client";

// Gom đúng 1 chỗ mẫu `err instanceof ApiError ? err.message : String(err)` vốn
// lặp lại ~40 lần trong các trang. ApiError.message chính là `detail` đã bóc
// từ response backend (xem api/client.ts:request); mọi lỗi khác (mạng, lỗi JS)
// rơi về String().
export function errMessage(err: unknown): string {
  return err instanceof ApiError ? err.message : String(err);
}
