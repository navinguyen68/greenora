# GREENORA V34 — Giao diện ấm áp như về nhà

Phiên bản kế thừa GREENORA V33, giữ nguyên quản trị hợp nhất, căn hộ, dịch vụ, tìm phòng, thay banner.

## Chạy thử
1. Dừng máy chủ cũ bằng Ctrl+C.
2. Giải nén ZIP vào thư mục mới.
3. Nếu có dữ liệu V33, sao lưu rồi sao chép thư mục `data` và `public/uploads` cũ sang V34 (không xóa dữ liệu gốc).
4. Mở PowerShell tại thư mục chứa `server.py`, chạy `python server.py`.
5. Mở http://127.0.0.1:8765/ và nhấn Ctrl+F5 để cập nhật giao diện.
6. Admin: http://127.0.0.1:8765/admin

## Thiết kế
- Màu kem, xanh lá trầm, vàng champagne; nền banner ấm từ hình minh họa.
- Hình banner lưu tại `public/greenora-warm-home.jpg`; giao diện thay ảnh trong Admin vẫn hoạt động.
- Ảnh nền là ảnh minh họa ý tưởng, không phải ảnh căn hộ thực tế tại Ecopark.
- Trên điện thoại giao diện tự co giãn theo chiều rộng.

**Lưu ý:** Nếu trước đó đã thay banner trong Admin, ảnh đã tải lên sẽ được ưu tiên thay cho ảnh nền mặc định V34. Bạn có thể bấm **Khôi phục ảnh mặc định** trong Admin để xem giao diện mới.

Đây là bản chạy thử trên máy cá nhân, không phải hệ thống triển khai công khai đã kiểm thử bảo mật.
