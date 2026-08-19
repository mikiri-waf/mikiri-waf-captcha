1. Install as needed depending on:

```bash
apt update && apt install -y nginx python3 python3-venv python3-pip memcached
python3 -m venv /var/www/mikiri-waf-captcha/venv
/var/www/mikiri-waf-captcha/venv/bin/python3 -m pip install --upgrade pip
/var/www/mikiri-waf-captcha/venv/bin/python3 -m pip install -r /var/www/mikiri-waf-captcha/requirements.txt
```

2. Download Mikiri WAF CAPTCHA from the GitHub repository and configure it:

```bash
cd /var/www/
git clone https://github.com/mikiri-waf/mikiri-waf-captcha
mkdir -p /var/log/mikiri-waf/captcha
chmod -R 0750 /var/log/mikiri-waf/captcha
chown -R www-data:www-data /var/log/mikiri-waf/captcha
cp /var/www/mikiri-waf-captcha/misc/captcha /etc/logrotate.d/
cp /var/www/mikiri-waf-captcha/misc/captcha.service /lib/systemd/system/
```

3. Set the proxy server address (if used) in the configuration file `/var/www/mikiri-waf-captcha/settings.py`:

```bash
proxy = 'http://proxy.example.com:3128'
```

4. Run the application:

```bash
systemctl enable mikiri-waf-captcha
systemctl start mikiri-waf-captcha
```

5. Check status and log for errors:

```bash
systemctl status mikiri-waf-captcha
cat /var/log/mikiri-waf/captcha/api.log
netstat -nlp | grep 8080