Output docs/demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 1080
Set Height 340
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

Env CLICOLOR_FORCE "1"
Env PATH "/home/kaidev/桌面/app_info/build:/usr/local/bin:/usr/bin:/bin"

Type "cd /home/kaidev/桌面/app_info && clear"
Enter
Sleep 1s

# 1. 基础信息
Type "app_info show test/wechat.apk"
Enter
Sleep 3s

# 2. 加权限
Ctrl+L
Type "app_info show test/wechat.apk --perms"
Enter
Sleep 3s

# 3. 加签名
Ctrl+L
Type "app_info show test/wechat.apk --sigs"
Enter
Sleep 3s

# 4. 证书 + openssl 验证
Ctrl+L
Type "app_info cert test/wechat.apk /tmp/"
Enter
Sleep 3s

Type "openssl x509 -inform DER -in /tmp/cert_0_v2.der -noout -fingerprint -sha256"
Enter
Sleep 3s