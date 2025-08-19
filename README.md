# VibloCTF-Writeups
## Contents
### Web
- [Web 7](https://github.com/DucThinh47/VibloCTF-Writeups#web-7)
- [We're out of idea, let's call it Web2](https://github.com/DucThinh47/VibloCTF-Writeups/tree/main#were-out-of-idea-lets-call-it-web2)
- [Tricky Sneaky Weby](https://github.com/DucThinh47/VibloCTF-Writeups/tree/main#tricky-sneaky-weby)
- [Web 11](https://github.com/DucThinh47/VibloCTF-Writeups/tree/main#web-11)
- [It's OT TIME!](https://github.com/DucThinh47/VibloCTF-Writeups/tree/main#its-ot-time)
#### Web 7

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image0.png?raw=true)

Tôi đã kiểm tra source code, cookie nhưng không tìm được gì. Thử truy cập `/robots.txt`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image1.png?raw=true)

=> Tìm được path `/index.abc`, tôi sẽ truy cập thử:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image2.png?raw=true)

Nội dung là một đoạn code PHP, phân tích qua có thể thấy:

- NUL byte injection (do ereg không binary-safe)
    - `ereg("^[a-zA-Z0-9]+$", $password)` sẽ dừng ở ký tự `NUL \0`
    - Có thể đưa chuỗi password có dạng: phần đầu chỉ chữ/số, sau đó chèn `\0`, rồi mới đến `^_^`
    - Kết quả:
        -   `ereg` chỉ nhìn thấy phần trước `\0` (toàn alphanumeric) => không vào báo lỗi
        - `strpos` thì binary-safe, nhìn thấy cả phần sau `\0` => tìm được `'^_^'` => in flag.

Tôi thử nhập `/?password=abc%00^_^` và tìm được flag:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image3.png?raw=true)

#### We're out of idea, let's call it Web2

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image4.png?raw=true)

Thử thách này sẽ yêu cầu chuyển đủ số tiền mới lấy được flag. Ban đầu tài khoản chỉ có 10$, tôi gửi số tiền này đi và kiểm tra request:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image5.png?raw=true)

Trong request body có 2 tham số là `money` và `rescue`. Tôi thử thay đổi giá trị tham số `rescue` thành `none` và `money` thành `$299999998`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image6.png?raw=true)

=> Thành công. Tiếp theo chỉ việc gửi số tiền theo yêu cầu và tìm được flag:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image7.png?raw=true)
#### Tricky Sneaky Weby

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image8.png?raw=true)

Mật khẩu của level 1 đã được cho sẵn là `SUN$HELL`, tuy nhiên khi xem source code, tôi thầy rằng dù nhập chữ hoa thì server sẽ luôn ép chuyển về chữ thường thông qua đoạn mã JS:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image9.png?raw=true)

Tôi đã Disable JS thông qua Devtool vừa vượt qua level 1:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image10.png?raw=true)

Sang level 2, mật khẩu đã bị lộ trong source code, được mã hóa dưới dạng base64:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image11.png?raw=true)

Giải mã, điền mật khẩu và tôi tìm được flag:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image12.png?raw=true)

Tuy nhiên, đây không phải flag thật, tôi tiếp tục tìm hiểu source code thì vẫn còn một thử thách nữa:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image13.png?raw=true)

Sang level tiếp theo, trong chuỗi mật khẩu có những khoảng trắng, đồng thời server không cho copy patse mật khẩu để dán vào. 

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image14.png?raw=true)

Tôi sử dụng console trong devtool và thực thi lệnh để lấy mật khẩu không chứa những ký tự khác:

    document.getElementById("password").innerText.replace(/[^\x20-\x7E]/g,"")

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image15.png?raw=true)

Sau đó sử dụng Burp Suite để gửi POST request và tìm được flag:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image16.png?raw=true)
#### Web 11

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image17.png?raw=true)

Kiểm tra source code, tôi tìm được path `/1.php`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image18.png?raw=true)

Truy cập trang này:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image19.png?raw=true)

Khi kiểm tra source code, tôi thấy nó hoàn toàn bị mã hóa, khi thử reload lại trang tôi thấy 1 ảnh khác được hiển thị rất nhanh xong lại biến mất, để ý kỹ thì bức ảnh này sẽ chứa flag.
#### It's OT TIME!

![img](20)

Thử click `View the source`:

![img](21)

Một đoạn code PHP, thông qua đoạn code này, tôi hiểu rằng mình phải truyền tham số `/?magic_command` với giá trị đúng bằng `HomNayOT_EmNhe` thì mới lấy được flag, tuy nhiên nếu nhập y nguyên thì server sẽ không chấp nhận. Do đó, tôi thử lồng chính chuỗi này vào chính nó `/? magic_command=HomNayOTHomNayOT_EmNhe_EmNhe` và tìm được flag:

![img](22)







