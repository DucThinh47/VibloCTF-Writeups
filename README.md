# VibloCTF-Writeups
## Contents
### Web
- [Web 7]()
- [Web 2]()
#### Web 7

![img](0)

Tôi đã kiểm tra source code, cookie nhưng không tìm được gì. Thử truy cập `/robots.txt`:

![img](1)

=> Tìm được path `/index.abc`, tôi sẽ truy cập thử:

![img](2)

Nội dung là một đoạn code PHP, phân tích qua có thể thấy:

- NUL byte injection (do ereg không binary-safe)
    - `ereg("^[a-zA-Z0-9]+$", $password)` sẽ dừng ở ký tự `NUL \0`
    - Có thể đưa chuỗi password có dạng: phần đầu chỉ chữ/số, sau đó chèn `\0`, rồi mới đến `^_^`
    - Kết quả:
        -   `ereg` chỉ nhìn thấy phần trước `\0` (toàn alphanumeric) => không vào báo lỗi
        - `strpos` thì binary-safe, nhìn thấy cả phần sau `\0` => tìm được `'^_^'` => in flag.

Tôi thử nhập `/?password=abc%00^_^` và tìm được flag:

![img](3)

#### Web 2

![img](4)

Thử thách này sẽ yêu cầu chuyển đủ số tiền mới lấy được flag. Ban đầu tài khoản chỉ có 10$, tôi gửi số tiền này đi và kiểm tra request:

![img](5)

Trong request body có 2 tham số là `money` và `rescue`. Tôi thử thay đổi giá trị tham số `rescue` thành `none` và `money` thành `$299999998`:

![img](6)

=> Thành công. Tiếp theo chỉ việc gửi số tiền theo yêu cầu và tìm được flag:

![img](7)






