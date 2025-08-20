# VibloCTF-Writeups
## Contents
### Web
- [Web7]()
- [We're out of idea, let's call it Web2](https://github.com/DucThinh47/VibloCTF-Writeups/tree/main#were-out-of-idea-lets-call-it-web2)
- [Tricky Sneaky Weby](https://github.com/DucThinh47/VibloCTF-Writeups/tree/main#tricky-sneaky-weby)
- [Web11]()
- [It's OT TIME!](https://github.com/DucThinh47/VibloCTF-Writeups/tree/main#its-ot-time)
- [Sun* Service](https://github.com/DucThinh47/VibloCTF-Writeups/tree/main#sun-service)
- [Web13]()
- [Web6]()
#### Web7

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
#### Web11

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image17.png?raw=true)

Kiểm tra source code, tôi tìm được path `/1.php`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image18.png?raw=true)

Truy cập trang này:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image19.png?raw=true)

Khi kiểm tra source code, tôi thấy nó hoàn toàn bị mã hóa, khi thử reload lại trang tôi thấy 1 ảnh khác được hiển thị rất nhanh xong lại biến mất, để ý kỹ thì bức ảnh này sẽ chứa flag.
#### It's OT TIME!

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image20.png?raw=true)

Thử click `View the source`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image21.png?raw=true)

Một đoạn code PHP, thông qua đoạn code này, tôi hiểu rằng mình phải truyền tham số `/?magic_command` với giá trị đúng bằng `HomNayOT_EmNhe` thì mới lấy được flag, tuy nhiên nếu nhập y nguyên thì server sẽ không chấp nhận. Do đó, tôi thử lồng chính chuỗi này vào chính nó `/? magic_command=HomNayOTHomNayOT_EmNhe_EmNhe` và tìm được flag:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image22.png?raw=true)
#### Sun* Service

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image23.png?raw=true)

Là một trang web cho phép ping các domain được nhập. Tôi sẽ thử chèn thêm lệnh bằng cách nhập `google.com;id`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image24.png?raw=true)

=> Có thể lợi dụng lỗ hổng Command Injection, tiếp theo tôi thử chèn `;ls`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image25.png?raw=true)

Tìm được file `index.php`, tôi sẽ thử đọc nó bằng cách chèn `;cat index.php`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image26.png?raw=true)

Không đọc được, có thể bên server có filter, tôi thử bypass khoảng trắng bằng cách chèn `;tail${IFS}index.php` và tìm được flag:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image27.png?raw=true)
#### Web13

![img](28)

Trang web cho phép nhập URL và trả về request header và request body khi gửi request đến URL đó:

![img](29)

![img](30)

Tôi thử nhập `/etc/passwd` xem có in ra được nội dung không:

![img](31)

Không in ra được, có thể website yêu cầu bắt buộc phải nhập vào một URL (phải bắt đầu bằng http://, https://,...), tôi nghĩ đến `URI scheme file://` để biến đường dẫn file cục bộ thành một URL hợp lệ:

![img](32)

=> Thành công, tiếp theo tôi sẽ thử đọc nội dung file `index.php` bằng cách nhập: 

    file:///proc/self/cwd/index.php

Trong Linux có một cơ chế đặc biệt:
- `/proc/self/` là thư mục ảo chứa thông tin về chính tiến trình hiện tại.
- `/proc/self/cwd/` là một symlink (liên kết tượng trưng) trỏ tới current working directory (CWD) của tiến trình đó
- Với tiến trình PHP hoặc webserver, `cwd` thường chính là thư mục webroot (chứa `index.php`, `config.php`, …)
- Nội dung file `index.php:

        "<?php
        @error_reporting(E_ALL^E_NOTICE);
        @ini_set('display_errors', 1);
        include 'config.php';

        function unparse_url($parsed_url)
        {
        $scheme   = isset($parsed_url['scheme']) ? $parsed_url['scheme'] . '://' : '';
        $host     = isset($parsed_url['host']) ? $parsed_url['host'] : '';
        $port     = isset($parsed_url['port']) ? ':' . $parsed_url['port'] : '';
        $user     = isset($parsed_url['user']) ? $parsed_url['user'] : '';
        $pass     = isset($parsed_url['pass']) ? ':' . $parsed_url['pass']  : '';
        $pass     = ($user || $pass) ? "$pass@" : '';
        $path     = isset($parsed_url['path']) ? $parsed_url['path'] : '';
        $query    = isset($parsed_url['query']) ? '?' . $parsed_url['query'] : '';
        $fragment = isset($parsed_url['fragment']) ? '#' . $parsed_url['fragment'] : '';
        return "$scheme$user$pass$host$port$path$query$fragment";
        }

        function curl_get($url)
        {
        try {
            $url  = parse_url($url);
            if (!in_array($url['scheme'], ['file', 'http', 'https'])) return [];
            $url = unparse_url($url);
            $ch = curl_init();
            curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HEADER => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 1,
            CURLOPT_ENCODING => '',
            CURLOPT_HTTPHEADER => [
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
                'Accept-Encoding: gzip, deflate',
                'Accept-Language: vi,vi-VN;q=0.9,en-US;q=0.8,en;q=0.7',
                'Cache-Control: no-cache',
                'Connection: keep-alive',
                'DNT: 1',
                'Pragma: no-cache',
                'Referer: '.$url,
                'Sec-Fetch-Mode: navigate',
                'Sec-Fetch-Site: cross-site',
                'Sec-Fetch-User: ?1',
                'Upgrade-Insecure-Requests: 1',
                'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            ],
            ]);
            $raw = curl_exec($ch);
            $headers = '';
            $content = '';
            $rnrn = strpos($raw, "\r\n\r\n");
            if ($rnrn === false) {
            $headers = $raw;
            } else {
            $headers = substr($raw, 0, $rnrn);
            $content = substr($raw, $rnrn + 4);
            }
            $error = curl_error($ch);
            $info = curl_getinfo($ch);
            curl_close($ch);
            return [
            'raw' => $raw,
            'headers' => $headers,
            'content' => $content,
            'error' => $error,
            'info' => $info,
            ];
        } catch (Exception $e) {
            return [];
        }
        }
        if (isset($_POST['debug_url']) && isset($_POST['debug_field'])) {
        $info = curl_get($_POST['debug_url']);
        echo 'Here is your debug informations:<br/><pre>';
        if(isset($info['error']) && $info['error']) {
            echo 'Error: ',$info['error'], "\r\n\r\n";
        }
        var_dump(htmlentities($info[$_POST['debug_field']]));
        echo '</pre>';
        }
        ?>
        <h2>Debug your webhook</h2>
        <form method=post>
        <label>URL: <input name=debug_url placeholder="Debug URL" value="<?php echo htmlentities($_POST['debug_url']??''); ?>"></label>
        <br>
        <br>
        <label>  
        Field:
        <select name=debug_field>
            <option value="headers">HEADER</option>
            <option value="content" selected>BODY</option>
        </select>
        <br>
        <br>
        <button type=submit>DEBUG</button>
        </label>
        <br>
        <br>"
Không thu được gì từ `index.php`. Tiếp theo tôi thử đọc file hệ thống `config.php` và tìm được flag:

![img](33)
#### Web6

![img](34)

Tôi thử nhập `admin:admin`:

![img](35)

Tìm được một session cookie, tôi thử xem source code và tìm được đường dẫn để tải source code về:

![img](36)

Sau khi tải, tôi tìm được file `run.py` có nội dung sau:

    from flask import Flask, render_template, session, request, redirect, url_for
    from functools import wraps

    app = Flask(__name__)
    app.secret_key = 'xxx'

    def login_required(function):
        @wraps(function)
        def wrap(*args, **kwargs):
            if (not 'username' in session) and (request.endpoint != 'login' and '/static/' not in request.path):
                return redirect(url_for('login'))
            else:
                return function(*args, **kwargs)
        return wrap

    @app.route('/login',methods=['GET','POST'])
    def login():
        if request.method == "GET":
            return render_template('login.html')
        else:
            username = request.form['u']
            password = request.form['p']
            if 's_username' not in session or 's_password' not in session:
                session['s_username'] = 'xxx'
                session['s_password'] = 'xxx'

            session['username'] = username
            session['password'] = password
            return redirect(url_for('index'))

    @app.route('/logout',methods=['GET','POST'])
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.route('/',methods=['GET','POST'])
    @login_required
    def index():
        if 'username' in session:
            if session['username'] == session['s_username'] and session['password'] == session['s_password']:
                flag = 'xxx'
                return render_template('index.html',session=session,flag=flag)

        return render_template('index.html')

    if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0',port=5000)

Dựa vào đoạn code có thể thấy:
- Flag sẽ trả về nếu `username=s_username` và `password=s_password`
- `s_username` và `s_password` không lấy từ DB hay file gì cả => nó chỉ được set vào session lần đầu
- Tức là cả `s_username/s_password` và `username/password` đều cùng nằm trong session, và session lại được client giữ (Flask session cookie)
- Flask session dùng `app.secret_key ('xxx')` để sign dữ liệu session.
=> Nếu biết secret key, tôi có thể tự tạo một session cookie chứa `s_username=something`, `s_password=something`, `username=something`, `password=something` để bypass check và nhận flag

Tôi sẽ dùng `Flask-unsign` để brute-force secret key:

![img](37)

Tuy nhiên lại tìm được cả `s_username` và `s_password`, tôi login bằng thông tin này và tìm được flag:

![img](38)






