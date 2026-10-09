#!/usr/bin/env bash
# Mailroom: установка/обновление панели и подключение Postfix + Dovecot + Rspamd к её базе.
# Debian 13. Запуск из каталога репозитория:
#   sudo bash deploy/install.sh --hostname mail.example.com --ip 192.0.2.10
# Повторный запуск безопасен: секреты, CA и ключи не перевыпускаются, старые конфиги
# сохраняются в /root/mailroom-backup-<время>.
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 022
trap 'echo "Ошибка в строке $LINENO" >&2' ERR

HOSTNAME_FQDN='' LAN_IP='' PORT=5080
while (($#)); do
  case $1 in
    --hostname) HOSTNAME_FQDN=$2; shift 2;;
    --ip) LAN_IP=$2; shift 2;;
    --port) PORT=$2; shift 2;;
    *) echo "Неизвестный параметр $1" >&2; exit 1;;
  esac
done
((EUID == 0)) || { echo 'Запустите от root' >&2; exit 1; }
SRC=$(cd "$(dirname "$0")/.." && pwd)
APP=/opt/mailroom DATA=/var/lib/mailroom ETC=/etc/mailroom ENVF=/etc/mailroom.env
BACKUP=/root/mailroom-backup-$(date +%Y%m%d-%H%M%S)
[[ -n $HOSTNAME_FQDN ]] || HOSTNAME_FQDN=$(postconf -h myhostname 2>/dev/null || hostname -f)
[[ -n $LAN_IP ]] || LAN_IP=$(hostname -I | awk '{print $1}')
[[ $HOSTNAME_FQDN =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]] || { echo "Некорректное имя: $HOSTNAME_FQDN" >&2; exit 1; }
echo "== Mailroom: $HOSTNAME_FQDN ($LAN_IP), порт $PORT"

# Непривилегированный LXC: sandbox пространств имён systemd недоступен (status=226/NAMESPACE).
# Для такого сервиса подкладываем drop-in без изоляции — только если он иначе не стартует.
start_with_lxc_fallback() {
  local unit=$1
  systemctl enable -q "$unit"
  systemctl reset-failed "$unit" 2>/dev/null || true
  # Для Type=simple restart «успешен» до падения процесса — проверяем состояние через пару секунд.
  systemctl restart "$unit" || true
  sleep 3
  systemctl is-active -q "$unit" && return 0
  journalctl -u "$unit" -n 30 --no-pager | grep -q NAMESPACE || return 1
  install -d "/etc/systemd/system/$unit.service.d"
  cat > "/etc/systemd/system/$unit.service.d/lxc.conf" <<'EOF'
[Service]
PrivateTmp=no
PrivateDevices=no
ProtectHome=no
ProtectSystem=no
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectControlGroups=no
ProtectHostname=no
ProtectClock=no
ProtectKernelLogs=no
PrivateUsers=no
RestrictNamespaces=no
ProtectProc=default
ProcSubset=all
ReadWritePaths=
ReadOnlyPaths=
NoExecPaths=
ExecPaths=
EOF
  systemctl daemon-reload
  systemctl reset-failed "$unit"
  systemctl restart "$unit"
  sleep 2
  systemctl is-active -q "$unit"
}

echo '== Пакеты'
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq postfix postfix-pgsql dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd \
  dovecot-pgsql dovecot-sieve dovecot-managesieved rspamd redis-server postgresql sudo fail2ban radicale \
  python3-flask python3-psycopg2 python3-passlib python3-cryptography gunicorn dnsutils openssl gnupg openssh-client >/dev/null

mkdir -p "$BACKUP"
cp -a /etc/postfix /etc/dovecot /etc/rspamd "$BACKUP/" 2>/dev/null || true
[[ -f $ENVF ]] && cp -a "$ENVF" "$BACKUP/"
echo "   резервная копия конфигов: $BACKUP"

echo '== Пользователи и каталоги'
getent group vmail >/dev/null || groupadd --system --gid 5000 vmail
getent passwd vmail >/dev/null || useradd --system --uid 5000 --gid vmail --home-dir /var/vmail --no-create-home --shell /usr/sbin/nologin vmail
install -d -o vmail -g vmail -m 0750 /var/vmail
getent passwd mailroom >/dev/null || useradd --system --home-dir $APP --shell /usr/sbin/nologin mailroom
usermod -aG systemd-journal mailroom
# 0711: Rspamd (_rspamd) должен пройти к $DATA/dkim, но не видеть список файлов.
install -d -o mailroom -g mailroom -m 0711 $DATA
install -d -o mailroom -g _rspamd -m 2750 $DATA/dkim
install -d -m 0755 $ETC
install -d -m 0750 -o root -g mailroom $ETC/tls

echo '== Сертификат (собственный CA для внутренней сети)'
# Строгие клиенты (Python 3.13, современные браузеры) требуют у CA keyUsage=keyCertSign.
if [[ -f $ETC/ca/ca.crt ]] && ! openssl x509 -in $ETC/ca/ca.crt -noout -ext keyUsage 2>/dev/null | grep -q 'Certificate Sign'; then
  mv $ETC/ca "$BACKUP/ca-old"; rm -f $ETC/tls/server.crt
fi
if [[ ! -f $ETC/ca/ca.key ]]; then
  install -d -m 0700 $ETC/ca
  openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=Mailroom CA $HOSTNAME_FQDN" \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' -keyout $ETC/ca/ca.key -out $ETC/ca/ca.crt 2>/dev/null
fi
if [[ ! -f $ETC/tls/server.crt ]] || ! openssl x509 -in $ETC/tls/server.crt -noout -checkend 2592000 >/dev/null \
   || ! openssl x509 -in $ETC/tls/server.crt -noout -ext subjectAltName | grep -q "DNS:$HOSTNAME_FQDN"; then
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$HOSTNAME_FQDN" -keyout $ETC/tls/server.key -out $ETC/tls/server.csr 2>/dev/null
  printf 'subjectAltName=DNS:%s,DNS:%s,IP:%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n' \
    "$HOSTNAME_FQDN" "$(hostname -f)" "$LAN_IP" > $ETC/tls/ext.cnf
  openssl x509 -req -in $ETC/tls/server.csr -CA $ETC/ca/ca.crt -CAkey $ETC/ca/ca.key -CAcreateserial \
    -days 825 -extfile $ETC/tls/ext.cnf -out $ETC/tls/server.crt 2>/dev/null
  cat $ETC/tls/server.crt $ETC/ca/ca.crt > $ETC/tls/fullchain.pem
  rm -f $ETC/tls/server.csr
fi
cp $ETC/ca/ca.crt $ETC/tls/ca.crt
chown root:mailroom $ETC/tls/*; chmod 0640 $ETC/tls/server.key; chmod 0644 $ETC/tls/*.crt $ETC/tls/fullchain.pem
# Сам сервер доверяет своему CA: проверки TLS из панели и локальные клиенты.
cp $ETC/ca/ca.crt /usr/local/share/ca-certificates/mailroom-ca.crt && update-ca-certificates >/dev/null

echo '== Секреты'
secret() { openssl rand -hex 32; }
touch $ENVF; chmod 0640 $ENVF; chown root:mailroom $ENVF
getval() { grep -E "^$1=" $ENVF | tail -1 | cut -d= -f2- || true; }
setval() { if grep -qE "^$1=" $ENVF; then sed -i "s|^$1=.*|$1=$2|" $ENVF; else echo "$1=$2" >> $ENVF; fi; }
MASTER=$(getval MAILROOM_IMAP_MASTER_PASSWORD); [[ -n $MASTER ]] || MASTER=$(secret)
setval MAILROOM_IMAP_MASTER_PASSWORD "$MASTER"
setval MAILROOM_DATA_DIR $DATA
setval MAILROOM_CA_CERT $ETC/tls/ca.crt
setval MAILROOM_COOKIE_SECURE 1
sed -i '/^MAIL_GATEWAY_/d; /^MAILROOM_ADMIN_PASSWORD=/d' $ENVF
[[ -f $ETC/mailserver.pass ]] || (umask 077; secret > $ETC/mailserver.pass)
DBPASS=$(cat $ETC/mailserver.pass)

echo '== База: роль mailserver только для чтения представлений'
runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 -d mailroom <<SQL
DO \$\$BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mailserver') THEN
    CREATE ROLE mailserver LOGIN PASSWORD '$DBPASS';
  ELSE
    ALTER ROLE mailserver PASSWORD '$DBPASS';
  END IF;
END\$\$;
GRANT CONNECT ON DATABASE mailroom TO mailserver;
GRANT USAGE ON SCHEMA public TO mailserver;
SQL

echo '== Код панели'
install -d -o mailroom -g mailroom -m 0755 $APP
for f in .session-secret .bootstrap-admin; do
  [[ -f $APP/$f && ! -f $DATA/$f ]] && mv $APP/$f $DATA/$f
done
rm -f $APP/.bootstrap-mailboxes $APP/setup_runner.py $APP/setup_profile.json
rm -rf $APP/__pycache__ $APP/templates $APP/static
cp -r "$SRC"/app.py "$SRC"/mailcore.py "$SRC"/webmail.py "$SRC"/mailroom_cli.py "$SRC"/templates "$SRC"/static "$SRC"/docs "$SRC"/README.md $APP/
chown -R root:root $APP; chmod -R go-w $APP
chown -R mailroom:mailroom $DATA/.session-secret $DATA/.bootstrap-admin 2>/dev/null || true
install -m 0755 "$SRC"/deploy/mailroom-helper /usr/local/sbin/mailroom-helper
install -m 0750 "$SRC"/deploy/mailroom-backup /usr/local/sbin/mailroom-backup
cat > /usr/local/sbin/mailroom <<'EOF'
#!/bin/sh
# Консольная утилита Mailroom: mailroom --help
[ "$(id -u)" = 0 ] || { echo 'Запустите от root: sudo mailroom ...' >&2; exit 1; }
case "$1" in
  backup) exec /usr/local/sbin/mailroom-backup ;;
  restore) exec /usr/local/sbin/mailroom-backup --restore "$2" ;;
esac
set -a; . /etc/mailroom.env; set +a
cd /opt/mailroom && exec runuser -u mailroom -- /usr/bin/python3 /opt/mailroom/mailroom_cli.py "$@"
EOF
chmod 0750 /usr/local/sbin/mailroom
# Ключ для отправки копий на другой сервер: публичную часть панель показывает администратору.
[[ -f $ETC/backup_ed25519 ]] || ssh-keygen -q -t ed25519 -N '' -C "mailroom-backup@$HOSTNAME_FQDN" -f $ETC/backup_ed25519
install -o mailroom -g mailroom -m 0644 $ETC/backup_ed25519.pub $DATA/backup_ed25519.pub
[[ -s $ETC/backup.pass ]] || (umask 077; openssl rand -base64 33 > $ETC/backup.pass)
cat > /etc/systemd/system/mailroom-backup.service <<'EOF'
[Unit]
Description=Mailroom: резервная копия почты, базы и ключей
After=postgresql.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mailroom-backup
Nice=10
IOSchedulingClass=idle
EOF
cat > /etc/systemd/system/mailroom-backup.timer <<'EOF'
[Unit]
Description=Mailroom: ежедневная резервная копия
[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=20min
Persistent=true
[Install]
WantedBy=timers.target
EOF
cat > /etc/systemd/system/mailroom-check.service <<EOF
[Unit]
Description=Mailroom: проверка сервера и оповещения
After=mailroom.service
[Service]
Type=oneshot
User=mailroom
Group=mailroom
WorkingDirectory=$APP
EnvironmentFile=$ENVF
ExecStart=/usr/bin/python3 $APP/mailroom_cli.py check
EOF
cat > /etc/systemd/system/mailroom-check.timer <<'EOF'
[Unit]
Description=Mailroom: проверка каждые 15 минут
[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
[Install]
WantedBy=timers.target
EOF
cat > /etc/sudoers.d/mailroom <<EOF
mailroom ALL=(root) NOPASSWD: /usr/local/sbin/mailroom-helper
EOF
chmod 0440 /etc/sudoers.d/mailroom
visudo -cf /etc/sudoers.d/mailroom >/dev/null

echo '== Запуск панели (создаёт схему и представления)'
cat > /etc/systemd/system/mailroom.service <<EOF
[Unit]
Description=Mailroom — панель почтового сервера и веб-почта
After=network-online.target postgresql.service dovecot.service postfix.service
Wants=network-online.target

[Service]
Type=exec
User=mailroom
Group=mailroom
WorkingDirectory=$APP
EnvironmentFile=$ENVF
ExecStart=/usr/bin/gunicorn --workers 3 --threads 16 --worker-class gthread --timeout 90 \\
  --bind $LAN_IP:$PORT --certfile $ETC/tls/server.crt --keyfile $ETC/tls/server.key \\
  --access-logfile - app:app
Restart=on-failure
RestartSec=3
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=$DATA
# sudo для mailroom-helper требует повышения прав, поэтому NoNewPrivileges не используется.

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable -q mailroom
systemctl enable -q --now mailroom-backup.timer mailroom-check.timer
systemctl restart mailroom
for i in $(seq 30); do
  runuser -u postgres -- psql -X -d mailroom -Atc "SELECT 1 FROM pg_views WHERE viewname='mail_users'" | grep -q 1 && break
  sleep 1
done
runuser -u postgres -- psql -X -q -d mailroom -c "GRANT SELECT ON mail_domains, mail_users, mail_aliases, mail_sender_login TO mailserver"

echo '== Postfix'
install -d -o root -g postfix -m 0750 /etc/postfix/sql
sqlmap() {
  cat > /etc/postfix/sql/$1.cf <<EOF
user = mailserver
password = $DBPASS
hosts = 127.0.0.1
dbname = mailroom
query = $2
EOF
}
sqlmap domains "SELECT domain FROM mail_domains WHERE domain='%s'"
sqlmap mailboxes "SELECT 1 FROM mail_users WHERE address='%s'"
sqlmap aliases "SELECT goto FROM mail_aliases WHERE address='%s'"
sqlmap sender-login "SELECT owner FROM mail_sender_login WHERE address='%s'"
chown root:postfix /etc/postfix/sql/*.cf; chmod 0640 /etc/postfix/sql/*.cf

while IFS= read -r line; do [[ -n $line ]] && postconf -e "$line"; done <<EOF
myhostname = $HOSTNAME_FQDN
myorigin = \$myhostname
mydestination = \$myhostname, localhost
inet_interfaces = all
mynetworks = 127.0.0.0/8
recipient_delimiter = +
message_size_limit = 26214400
mailbox_size_limit = 0
disable_vrfy_command = yes
smtpd_helo_required = yes
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
smtpd_recipient_restrictions = reject_non_fqdn_recipient, reject_unknown_recipient_domain, reject_unlisted_recipient
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = no
smtpd_sasl_security_options = noanonymous
smtpd_tls_auth_only = yes
smtpd_tls_security_level = may
smtpd_tls_chain_files = $ETC/tls/server.key, $ETC/tls/fullchain.pem
smtpd_tls_protocols = >=TLSv1.2
smtpd_tls_mandatory_protocols = >=TLSv1.2
smtpd_tls_loglevel = 1
smtp_tls_security_level = may
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
virtual_mailbox_domains = proxy:pgsql:/etc/postfix/sql/domains.cf
virtual_mailbox_maps = proxy:pgsql:/etc/postfix/sql/mailboxes.cf
virtual_alias_maps = proxy:pgsql:/etc/postfix/sql/aliases.cf
virtual_transport = lmtp:unix:private/dovecot-lmtp
smtpd_sender_login_maps = proxy:pgsql:/etc/postfix/sql/sender-login.cf
smtpd_milters = inet:127.0.0.1:11332
non_smtpd_milters = \$smtpd_milters
milter_protocol = 6
milter_default_action = tempfail
milter_mail_macros = i {mail_addr} {client_addr} {client_name} {auth_authen}
EOF
postconf -X smtpd_tls_cert_file smtpd_tls_key_file 2>/dev/null || true
if ! grep -qE '^submission[[:space:]]+inet' /etc/postfix/master.cf; then
  cat >> /etc/postfix/master.cf <<'EOF'
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o smtpd_sender_restrictions=reject_authenticated_sender_login_mismatch
EOF
fi
if ! grep -qE '^(submissions|465)[[:space:]]+inet' /etc/postfix/master.cf; then
  cat >> /etc/postfix/master.cf <<'EOF'
submissions inet n      -       y       -       -       smtpd
  -o syslog_name=postfix/submissions
  -o smtpd_tls_wrappermode=yes
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o smtpd_sender_restrictions=reject_authenticated_sender_login_mismatch
EOF
fi
postfix check

echo '== Dovecot 2.4'
MASTER_HASH=$(doveadm -O pw -s SHA512-CRYPT -p "$MASTER")
(umask 027; printf 'mailroom:%s::::::allow_real_nets=127.0.0.1/32\n' "$MASTER_HASH" > /etc/dovecot/master-users)
chown root:dovecot /etc/dovecot/master-users; chmod 0640 /etc/dovecot/master-users
install -d -m 0755 /etc/dovecot/sieve
cat > /etc/dovecot/sieve/spam.sieve <<'EOF'
require ["fileinto", "mailbox"];
# Письма, помеченные Rspamd как спам, — в папку «Спам».
if anyof (header :is "X-Spam" "Yes", header :contains "X-Spam-Flag" "YES") {
  fileinto :create "Junk";
  stop;
}
EOF
cat > /etc/dovecot/dovecot.conf <<EOF
# Управляется Mailroom (deploy/install.sh). Предыдущая версия — в $BACKUP.
dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0

protocols = imap pop3 lmtp sieve
listen = *

ssl = yes
ssl_min_protocol = TLSv1.2
ssl_server_cert_file = $ETC/tls/fullchain.pem
ssl_server_key_file = $ETC/tls/server.key

# Без TLS вход разрешён только с localhost (веб-почта Mailroom).
auth_allow_cleartext = no
auth_mechanisms = plain login
auth_username_format = %{user | lower}
auth_master_user_separator = *

mail_uid = vmail
mail_gid = vmail
first_valid_uid = 5000
mail_driver = maildir
mail_path = %{home}/Maildir
mailbox_list_index = yes

namespace inbox {
  inbox = yes
  separator = /
  mailbox Sent {
    auto = subscribe
    special_use = \Sent
  }
  mailbox Drafts {
    auto = subscribe
    special_use = \Drafts
  }
  mailbox Trash {
    auto = subscribe
    special_use = \Trash
  }
  mailbox Junk {
    auto = subscribe
    special_use = \Junk
  }
}

sql_driver = pgsql
pgsql 127.0.0.1 {
  parameters {
    user = mailserver
    password = $DBPASS
    dbname = mailroom
  }
}

# Мастер-пользователь для веб-почты: только с 127.0.0.1, пароль в /etc/mailroom.env.
passdb master {
  driver = passwd-file
  passwd_file_path = /etc/dovecot/master-users
  master = yes
  result_success = continue
}
passdb sql {
  default_password_scheme = SHA512-CRYPT
  query = SELECT address AS user, password FROM mail_users WHERE address = '%{user}'
}
userdb sql {
  query = SELECT home, quota_bytes || 'B' AS quota_storage_size FROM mail_users WHERE address = '%{user}'
  iterate_query = SELECT address AS user FROM mail_users
}

service imap-login {
  inet_listener imap {
    listen = 127.0.0.1
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
service pop3-login {
  inet_listener pop3 {
    port = 0
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}
service managesieve-login {
  inet_listener sieve {
    listen = 127.0.0.1
    port = 4190
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
protocol lmtp {
  postmaster_address = postmaster@$HOSTNAME_FQDN
  mail_plugins {
    sieve = yes
  }
}
mail_plugins {
  quota = yes
}
protocol imap {
  mail_plugins {
    imap_quota = yes
  }
}
quota user {
  driver = count
}
sieve_script personal {
  driver = file
  path = ~/sieve
  active_path = ~/.dovecot.sieve
}
sieve_script spam {
  type = before
  driver = file
  path = /etc/dovecot/sieve/spam.sieve
}
EOF
chmod 0640 /etc/dovecot/dovecot.conf; chown root:dovecot /etc/dovecot/dovecot.conf
sievec /etc/dovecot/sieve/spam.sieve
doveconf -n >/dev/null

echo '== Rspamd'
cat > /etc/rspamd/local.d/dkim_signing.conf <<EOF
# Ключи создаёт панель Mailroom. Подпись — только для доменов из selectors.map
# (после проверки публикации ключа в DNS).
path = "$DATA/dkim/\$domain.\$selector.key";
selector_map = "$DATA/dkim/selectors.map";
use_domain = "header";
use_esld = false;
sign_authenticated = true;
sign_local = true;
allow_username_mismatch = true;
allow_hdrfrom_mismatch = false;
try_fallback = false;
EOF
cat > /etc/rspamd/local.d/redis.conf <<'EOF'
servers = "127.0.0.1";
EOF
cat > /etc/rspamd/local.d/milter_headers.conf <<'EOF'
extended_spam_headers = true;
EOF
[[ -f $DATA/dkim/selectors.map ]] || install -o mailroom -g _rspamd -m 0640 /dev/null $DATA/dkim/selectors.map
rspamadm configtest >/dev/null

# Лимит отправки для авторизованных ящиков (587/465); меняется в панели → «Применить к Postfix».
LIMIT=$(runuser -u postgres -- psql -X -d mailroom -Atc "SELECT value FROM settings WHERE key='smtp_limit_hour'" 2>/dev/null || true)
/usr/local/sbin/mailroom-helper ratelimit-apply "${LIMIT:-100}" >/dev/null

echo '== Календарь и контакты (Radicale: CalDAV/CardDAV, вход паролем почты)'
install -d -o radicale -g radicale -m 0750 /etc/radicale/tls
install -o radicale -g radicale -m 0640 $ETC/tls/fullchain.pem $ETC/tls/server.key /etc/radicale/tls/
[[ -f /etc/radicale/config.dist ]] || cp /etc/radicale/config /etc/radicale/config.dist
cat > /etc/radicale/config <<EOF
# Управляется Mailroom (deploy/install.sh). Пакетный вариант: /etc/radicale/config.dist
[server]
hosts = 0.0.0.0:5232
ssl = True
certificate = /etc/radicale/tls/fullchain.pem
key = /etc/radicale/tls/server.key
max_content_length = 50000000

[encoding]
request = utf-8
stock = utf-8

[auth]
# Логин и пароль — те же, что у почтового ящика: проверка через IMAP Dovecot на localhost.
type = imap
imap_host = 127.0.0.1:143
imap_security = none
lc_username = True
cache_logins = True
delay = 2
realm = Mailroom

[rights]
type = owner_only

[storage]
filesystem_folder = /var/lib/radicale/collections

[web]
type = internal

[logging]
level = warning
EOF
start_with_lxc_fallback radicale
# Календарь и адресная книга по умолчанию для существующих ящиков.
runuser -u postgres -- psql -X -d mailroom -Atc "SELECT address FROM mail_users" | while read -r addr; do
  [[ -n $addr ]] && /usr/local/sbin/mailroom-helper dav-init "$addr" >/dev/null
done

echo '== Fail2ban'
cat > /etc/fail2ban/jail.d/mailroom.local <<'EOF'
[DEFAULT]
backend = systemd
banaction = nftables-multiport

[postfix-sasl]
enabled = true
port = 465,587
maxretry = 5
findtime = 10m
bantime = 1h

[dovecot]
enabled = true
port = 993,995
maxretry = 5
findtime = 10m
bantime = 1h
EOF
fail2ban-client -t >/dev/null

echo '== Перезапуск сервисов'
start_with_lxc_fallback redis-server
systemctl restart rspamd dovecot
systemctl restart postfix
systemctl enable -q fail2ban; systemctl restart fail2ban
systemctl restart mailroom

echo '== Проверки'
sleep 2
for s in postfix dovecot rspamd redis-server radicale fail2ban mailroom mailroom-backup.timer mailroom-check.timer; do printf '  %-13s %s\n' "$s" "$(systemctl is-active $s)"; done
ss -lntp | grep -E ':(25|465|587|993|995|143|4190|5232|'"$PORT"')\b' | awk '{print "  " $4}'
curl -s --cacert $ETC/tls/ca.crt "https://$LAN_IP:$PORT/api/health" --resolve "$HOSTNAME_FQDN:$PORT:$LAN_IP" >/dev/null \
  && echo "  панель: https://$LAN_IP:$PORT/  веб-почта: https://$LAN_IP:$PORT/mail" || echo '  панель не отвечает — journalctl -u mailroom'
[[ -f $DATA/.bootstrap-admin ]] && echo "  стартовый пароль администратора: $DATA/.bootstrap-admin"
echo "  корневой сертификат для клиентов: $ETC/tls/ca.crt (скачивается в веб-почте: /mail/ca.crt)"
echo '== Готово'
