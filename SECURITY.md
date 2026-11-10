# Chính sách bảo mật

## Báo cáo lỗ hổng

**Vui lòng không mở Issue công khai cho lỗ hổng bảo mật.**

Hãy báo cáo riêng qua tính năng *Private vulnerability reporting* của GitHub:
<https://github.com/kimanhtran-oss/safe-password-manager/security/advisories/new>

Nội dung nên có: mô tả lỗ hổng, các bước tái hiện (kèm file vault mẫu nếu có) và phiên bản Python, hệ điều hành đang dùng. Mình sẽ phản hồi trong vòng **7 ngày**.

Chỉ nhánh `main` được cập nhật bản vá.

## Mô hình đe dọa

### Tài sản cần bảo vệ

- Mật khẩu chính của người dùng.
- Các tài khoản và mật khẩu lưu trong vault.

### Đối tượng tấn công được xét tới

| Kẻ tấn công | Khả năng | Có bảo vệ không |
|---|---|---|
| **A1. Lấy được file vault** (máy bị trộm, file sao lưu bị lộ, bị chép trộm) | Đọc, sửa file; thử mật khẩu ngoài ứng dụng với tốc độ không giới hạn | ✅ Có |
| **A2. Gửi file vault độc hại** cho người dùng mở | Kiểm soát toàn bộ nội dung file | ✅ Có |
| **A3. Tiếp cận máy trong lúc người dùng vắng mặt** | Dùng bàn phím, chuột, xem màn hình | ✅ Phần lớn |
| **A4. Nhìn trộm màn hình** | Quan sát màn hình | ✅ Có |
| **A5. Đã cài mã độc trên máy** (keylogger, đọc RAM) | Toàn quyền trên máy | ❌ Ngoài phạm vi |

### Mối đe dọa và biện pháp

| Mối đe dọa | Biện pháp |
|---|---|
| A1 đọc dữ liệu trong file | Toàn bộ dữ liệu mã hóa bằng AES-256-GCM. File không chứa bản rõ, không chứa hash mật khẩu chính |
| A1 dò mật khẩu chính (brute force, từ điển) | scrypt với N = 2¹⁷ (khoảng 128 MB RAM mỗi lần thử); salt ngẫu nhiên chống bảng tra sẵn; yêu cầu mật khẩu chính tối thiểu 8 ký tự, khuyến nghị 12 |
| A1 sửa nội dung file để thay đổi dữ liệu | AES-GCM xác thực bản mã; phần đầu file được đưa vào AAD |
| A1 hạ tham số scrypt trong file để dò nhanh hơn | Tham số nằm trong AAD: sửa thì giải mã thất bại |
| A2 khai báo tham số scrypt khổng lồ để làm treo máy (DoS) | Kiểm tra giới hạn tham số **trước khi** chạy scrypt |
| A2 file sai định dạng làm ứng dụng lỗi | Kiểm tra định dạng và độ dài salt/nonce, báo lỗi có kiểm soát |
| A3 dùng vault đang mở | Tự khóa sau 5 phút không thao tác; khóa thì đóng mọi hộp thoại |
| A3 đoán mật khẩu chính qua giao diện | Tạm khóa sau 5 lần sai, thời gian chờ tăng gấp đôi |
| A3 đổi mật khẩu chính để chiếm vault | Phải nhập lại mật khẩu chính hiện tại |
| A4 nhìn thấy mật khẩu | Mật khẩu ẩn dạng `••••` theo mặc định |
| Mật khẩu nằm lại trong clipboard | Tự xóa clipboard sau 20 giây (không xóa nếu người dùng đã chép thứ khác) |
| Mất dữ liệu khi ghi file bị gián đoạn | Ghi file tạm, `fsync`, rồi thay thế |
| Mật khẩu ngẫu nhiên đoán được | Dùng `secrets` (CSPRNG), không dùng `random` |
| Thư viện có lỗ hổng đã công bố | Dependabot, `pip-audit` trong CI |
| Lỗi bảo mật trong mã nguồn | CodeQL, Bandit |

## Giới hạn đã biết

1. **Dữ liệu trong bộ nhớ**: Python không cho xóa hẳn chuỗi và bytes khỏi RAM. Sau khi khóa, bản sao có thể còn tồn tại cho tới khi bị ghi đè.
2. **Giới hạn số lần nhập sai** chỉ có tác dụng với A3. Với A1, lớp bảo vệ là độ chậm của scrypt và độ mạnh của mật khẩu chính.
3. **Clipboard** có thể bị phần mềm khác đọc trong thời gian chờ, và có thể bị lưu trong lịch sử clipboard của Windows (Win + V).
4. **A5** (máy đã nhiễm mã độc) nằm ngoài phạm vi bảo vệ của mọi trình quản lý mật khẩu chạy trên máy đó.
5. **Quên mật khẩu chính là mất dữ liệu.** Không có cơ chế khôi phục, đây là chủ đích thiết kế.
