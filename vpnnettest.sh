#!/bin/bash

#Database Details
HOST='68.168.220.124';
USER='vpnnetsh_BOLTNET';
PASS='E@j9gcYIW@CN';
DBNAME='vpnnetsh_BOLTNET';


echo -e "\e[1;32m Installing Server \033[0m"
sleep 3

echo -e "\033[01;31m Updating System \033[0m"

apt-get update -y > /dev/null 2>&1
chmod -x /etc/update-motd.d/*
apt-get install inxi screenfetch ansiweather -y  > /dev/null 2>&1

/bin/cat <<"EOM" >/etc/update-motd.d/01-custom
#!/bin/sh
/usr/bin/screenfetch
echo
echo "SYSTEM DISK USAGE"
export TERM=xterm; inxi -D
echo
echo "CURRENT WEATHER AT THE LOCATION"
ansiweather -l manila
EOM

chmod +x /etc/update-motd.d/01-custom

function ip_address(){
  IP="$( ip addr | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -E -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( curl -4 -s ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( curl -4 -s ipinfo.io/ip )"
  [ -n "${IP}" ] && echo "${IP}" || echo
  local IP
} 
MYIP=$(ip_address)

echo -e "\e[1;32m Done Updating \033[0m"
sleep 2

echo -e "\033[01;31m Allowing Downgrades \033[0m"
DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -q -y -u  -o Dpkg::Options::="--force-confdef" --allow-downgrades --allow-remove-essential --allow-change-held-packages --allow-unauthenticated > /dev/null 2>&1
echo -e "\e[1;32m Done Allowing Downgrades  \033[0m"
sleep 2

echo -e "\033[01;31m Installing Packages \033[0m"
apt install mysql-client php php-mysqli php-mysql php-gd php-mbstring -y
apt install php-ldap php-odbc php-pear php-xml php-xmlrpc php-mbstring php-snmp php-soap -y
apt install apache2 sudo nano fail2ban unzip python build-essential curl build-essential libwrap0-dev libpam0g-dev libdbus-1-dev libreadline-dev libnl-route-3-dev libprotobuf-c0-dev libpcl1-dev libopts25-dev autogen libgnutls28-dev libseccomp-dev libhttp-parser-dev php libapache2-mod-php -y
apt install screen openvpn easy-rsa -y
echo -e "\e[1;32m Done Installing Packages  \033[0m"
sleep 2

echo -e "\033[01;31m Compiling Openvpn Files \033[0m"
mkdir -p /etc/openvpn/easy-rsa/keys
mkdir -p /etc/openvpn/login
mkdir -p /etc/openvpn/radius
mkdir -p /var/www/html/stat
touch /etc/openvpn/server.conf
touch /etc/openvpn/server2.conf
touch /etc/openvpn/server3.conf

echo 'mode server 
tls-server 
port 110
proto udp 
dev tun
keepalive 1 180
max-clients 1000
resolv-retry infinite 
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh /etc/openvpn/easy-rsa/keys/dh2048.pem 
client-cert-not-required 
username-as-common-name 
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-env # 
tmp-dir "/etc/openvpn/" # 
server 172.20.0.0 255.255.255.0
push "redirect-gateway def1" 
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "sndbuf 393216"
push "rcvbuf 393216"
tun-mtu 1400 
mssfix 1360
verb 3
comp-lzo
script-security 3
up /etc/openvpn/update-resolv-conf                                                                                      
down /etc/openvpn/update-resolv-conf
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
log server_log
status /var/www/html/stat/udpstatus.txt
ifconfig-pool-persist /var/www/html/stat/ipp.txt' > /etc/openvpn/server.conf

echo 'mode server 
tls-server 
port 1194
proto tcp
dev tun
keepalive 1 180
max-clients 1000
resolv-retry infinite 
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh /etc/openvpn/easy-rsa/keys/dh2048.pem 
client-cert-not-required 
username-as-common-name 
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-env # 
tmp-dir "/etc/openvpn/" # 
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1" 
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "sndbuf 393216"
push "rcvbuf 393216"
tun-mtu 1400 
mssfix 1360
verb 3
comp-lzo
script-security 3
up /etc/openvpn/update-resolv-conf                                                                                      
down /etc/openvpn/update-resolv-conf
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
log server2_log
status /var/www/html/stat/status.txt
ifconfig-pool-persist /var/www/html/stat/ipp.txt' > /etc/openvpn/server2.conf

echo 'mode server 
tls-server 
port 1147
proto tcp
dev tun
keepalive 1 180
max-clients 1000
resolv-retry infinite 
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh /etc/openvpn/easy-rsa/keys/dh2048.pem 
client-cert-not-required 
username-as-common-name 
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-env # 
tmp-dir "/etc/openvpn/" # 
server 10.9.0.0 255.255.255.0
push "redirect-gateway def1" 
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "sndbuf 393216"
push "rcvbuf 393216"
tun-mtu 1400 
mssfix 1360
verb 3
comp-lzo
script-security 3
up /etc/openvpn/update-resolv-conf                                                                                      
down /etc/openvpn/update-resolv-conf
status /var/www/html/stat/udpstatus2.txt
client-connect /etc/openvpn/login/connect.sh
client-disconnect /etc/openvpn/login/disconnect.sh
log server3_log
ifconfig-pool-persist /var/www/html/stat/ipp.txt' > /etc/openvpn/server3.conf

cat <<\EOM >/etc/openvpn/login/config.sh
#!/bin/bash
HOST='DBHOST'
USER='DBUSER'
PASS='DBPASS'
DB='DBNAME'
EOM

sed -i "s|DBHOST|$HOST|g" /etc/openvpn/login/config.sh
sed -i "s|DBUSER|$USER|g" /etc/openvpn/login/config.sh
sed -i "s|DBPASS|$PASS|g" /etc/openvpn/login/config.sh
sed -i "s|DBNAME|$DBNAME|g" /etc/openvpn/login/config.sh

/bin/cat <<"EOM" >/etc/openvpn/login/auth_vpn
#!/bin/bash
. /etc/openvpn/login/config.sh
Query="SELECT user_name FROM users WHERE user_name='$username' AND auth_vpn=md5('$password') AND status='live' AND is_freeze=0 AND is_ban=0 AND (duration > 0 OR vip_duration > 0 OR private_duration > 0)"
user_name=`mysql -u $USER -p$PASS -D $DB -h $HOST -sN -e "$Query"`
[ "$user_name" != '' ] && [ "$user_name" = "$username" ] && echo "user : $username" && echo 'authentication ok.' && exit 0 || echo 'authentication failed.'; exit 1

EOM

#client-connect file
cat <<'LENZ05' >/etc/openvpn/login/connect.sh
#!/bin/bash

tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/login/config.sh

##set status online to user connected
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_active='1' AND device_connected='1' WHERE user_name='$common_name' "

LENZ05

#TCP client-disconnect file
cat <<'LENZ06' >/etc/openvpn/login/disconnect.sh
#!/bin/bash
tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/login/config.sh

mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_active='0' WHERE user_name='$common_name' "
LENZ06


cat << EOF > /etc/openvpn/easy-rsa/keys/ca.crt
-----BEGIN CERTIFICATE-----
MIIExDCCA6ygAwIBAgIJAKyvksf/QCcwMA0GCSqGSIb3DQEBCwUAMIGcMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCUEgxEDAOBgNVBAcTB01heW5pbGExDjAMBgNVBAoT
BVRvbmRvMRQwEgYDVQQLEwtQaW5veUdyb3VuZDERMA8GA1UEAxMIVG9uZG8gQ0Ex
DzANBgNVBCkTBnNlcnZlcjEkMCIGCSqGSIb3DQEJARYVcGlub3lncm91bmRAZ21h
aWwuY29tMB4XDTE3MDYxNzEwMjMxM1oXDTI3MDYxNTEwMjMxM1owgZwxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJQSDEQMA4GA1UEBxMHTWF5bmlsYTEOMAwGA1UEChMF
VG9uZG8xFDASBgNVBAsTC1Bpbm95R3JvdW5kMREwDwYDVQQDEwhUb25kbyBDQTEP
MA0GA1UEKRMGc2VydmVyMSQwIgYJKoZIhvcNAQkBFhVwaW5veWdyb3VuZEBnbWFp
bC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrfMyxOcaPROlq
TOrRfwixx/5vMdSyDh1b9j9zE/BDaWF1UtkZORXjI5YCdQNsk+86qHxVamZmC6jm
Tq5sC0XrZr725/qFANvj13rw7Bt3q+/Q5lCt5zwpuaSOem6YIlvqzBYbteShEaX8
h7ppL+bk6i+S9MOX5bc+m8zt0DwrLbC6tqBvC+1Btj8kvnhtoXI+uQoUxRa6PbsK
DcdW1iyjcjG+ARWKEXMSOjxL3RtWfoG6sRL4mkALNH/ghejvtXjYYeU3hUDyWGGy
QWux3WzreVYnoXyozEijwGPCCLdZ+Sdn8F4D7yXoPKsLxfqFvtt76zFVajNpszsX
cKbiBB5JAgMBAAGjggEFMIIBATAdBgNVHQ4EFgQUAvGhH/Tis+YRCGKQLUKaMcCE
hsgwgdEGA1UdIwSByTCBxoAUAvGhH/Tis+YRCGKQLUKaMcCEhsihgaKkgZ8wgZwx
CzAJBgNVBAYTAlVTMQswCQYDVQQIEwJQSDEQMA4GA1UEBxMHTWF5bmlsYTEOMAwG
A1UEChMFVG9uZG8xFDASBgNVBAsTC1Bpbm95R3JvdW5kMREwDwYDVQQDEwhUb25k
byBDQTEPMA0GA1UEKRMGc2VydmVyMSQwIgYJKoZIhvcNAQkBFhVwaW5veWdyb3Vu
ZEBnbWFpbC5jb22CCQCsr5LH/0AnMDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB
CwUAA4IBAQCa5JUgtw6j3poZEug6cV9Z/ndYqxvYkoOLNCaMG1xZYBch061qjqB1
8TvAqBpp4zF6w0i4P4Mwh1p+bUgOV04p7HB6aUMm14ALwn+hHhWlkVQ5bPqVEr9B
L8/xjcbBVGj1lgv6UCjzmx1Aq+VBlvy0wU1NQT3QuQXSIpEvGMAn3ApsNMmQQ8CW
hYWYMFbAcjF9vWi+FKoDtWQ6SyHvgcpkOuqWs4p9AEwI6WS1IpJPRiHIPYwAzA3u
824ER9Gn4OKoBLqVyhQvW3etMjMc/baWd6p0K06NSCwZsjchD+ayf5SjfUfhYTTM
llJ5x8d1nZT7CWpogTTvqDdK6iiKPb/+
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=PH, L=Maynila, O=Tondo, OU=PinoyGround, CN=Tondo CA/name=server/emailAddress=pinoyground@gmail.com
        Validity
            Not Before: Jun 17 10:23:30 2017 GMT
            Not After : Jun 15 10:23:30 2027 GMT
        Subject: C=US, ST=PH, L=Maynila, O=Tondo, OU=PinoyGround, CN=server/name=server/emailAddress=pinoyground@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:e2:78:00:40:ca:de:85:d3:2d:63:54:cc:3c:49:
                    72:98:a9:76:bd:1b:62:95:aa:36:1f:eb:b6:86:4b:
                    da:a9:c0:50:7b:c0:bf:3f:6f:d4:38:32:b9:ad:33:
                    b8:13:fb:6b:b8:41:c1:98:05:ac:3e:49:64:3e:1b:
                    9f:8f:07:b8:b5:b6:7c:86:59:be:a3:93:31:8c:b7:
                    77:b8:50:a4:b1:19:3b:34:a9:21:4a:a6:25:83:48:
                    60:cb:0d:1f:13:5b:d5:af:eb:2a:1d:55:41:8d:76:
                    c5:05:0d:98:7a:9a:f8:22:58:4c:11:01:99:e3:b3:
                    40:0a:9d:4c:cc:8b:1e:86:bf:9b:63:26:61:19:86:
                    5a:88:a9:99:93:66:0e:74:82:31:83:b3:7f:cc:cd:
                    57:03:e5:5b:ce:3c:97:5d:c8:62:c8:e8:94:d8:5a:
                    e9:a8:3b:be:ba:a6:b0:85:59:e4:10:d3:a2:c4:d3:
                    4d:fb:8f:a9:6e:98:bb:b6:69:9d:63:c4:01:df:46:
                    1a:5d:d2:26:b7:0f:3d:74:22:fe:bb:16:75:28:43:
                    ec:9c:e5:ad:d4:b6:af:42:eb:26:76:c6:83:29:b9:
                    d0:50:44:cd:f1:d1:0f:68:7b:2d:8c:86:7f:24:fc:
                    8f:4d:05:6e:47:8b:7c:c0:04:e1:e8:c9:97:4c:bb:
                    fe:a7
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                Easy-RSA Generated Server Certificate
            X509v3 Subject Key Identifier: 
                E0:C5:67:F2:F7:5D:B4:65:B8:71:0A:5D:58:C0:16:B5:09:D9:73:B7
            X509v3 Authority Key Identifier: 
                keyid:02:F1:A1:1F:F4:E2:B3:E6:11:08:62:90:2D:42:9A:31:C0:84:86:C8
                DirName:/C=US/ST=PH/L=Maynila/O=Tondo/OU=PinoyGround/CN=Tondo CA/name=server/emailAddress=pinoyground@gmail.com
                serial:AC:AF:92:C7:FF:40:27:30

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:server
    Signature Algorithm: sha256WithRSAEncryption
         3b:19:a5:22:34:0e:7b:51:12:8d:37:6e:10:19:58:d8:a1:3b:
         a2:c5:f8:62:3b:37:1d:06:5a:f3:a6:35:bd:0f:22:61:7d:e2:
         f3:54:00:a5:7b:9c:a7:e2:3b:e0:6f:35:a0:1d:23:02:c7:f0:
         2b:8a:b0:51:24:2d:87:b6:5d:ce:81:4a:f2:32:dd:42:a4:b5:
         f0:4d:1e:ac:5f:36:52:c9:c0:ba:1f:c7:3c:6a:f2:88:e1:14:
         1b:84:e7:53:84:ee:88:15:39:10:24:bc:8d:64:ca:65:75:55:
         0d:7d:09:dd:a3:d2:94:2b:d5:7e:46:72:70:91:69:02:a6:79:
         58:a1:4f:1b:18:c0:9a:4b:96:16:b2:70:a5:cd:bb:bf:33:b5:
         1a:76:51:93:8a:ca:4b:45:50:be:52:bd:28:cf:94:7e:d9:84:
         6c:93:43:b3:d0:2f:a5:3e:32:bd:0d:46:8a:d1:46:2d:64:f0:
         50:2f:c6:7d:54:54:88:3f:f5:02:17:71:6f:1c:4b:cd:2c:d4:
         c0:fc:39:15:bc:46:62:36:eb:d0:fe:fc:c2:c1:f5:fb:18:6f:
         7c:91:61:0e:2c:e1:17:08:44:9f:66:e4:d5:99:30:bf:f5:0a:
         96:b6:1e:8f:ea:c6:bb:6b:b4:0c:82:ef:ef:85:6e:74:94:c2:
         0c:2b:94:de
-----BEGIN CERTIFICATE-----
MIIFNTCCBB2gAwIBAgIBATANBgkqhkiG9w0BAQsFADCBnDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAlBIMRAwDgYDVQQHEwdNYXluaWxhMQ4wDAYDVQQKEwVUb25kbzEU
MBIGA1UECxMLUGlub3lHcm91bmQxETAPBgNVBAMTCFRvbmRvIENBMQ8wDQYDVQQp
EwZzZXJ2ZXIxJDAiBgkqhkiG9w0BCQEWFXBpbm95Z3JvdW5kQGdtYWlsLmNvbTAe
Fw0xNzA2MTcxMDIzMzBaFw0yNzA2MTUxMDIzMzBaMIGaMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCUEgxEDAOBgNVBAcTB01heW5pbGExDjAMBgNVBAoTBVRvbmRvMRQw
EgYDVQQLEwtQaW5veUdyb3VuZDEPMA0GA1UEAxMGc2VydmVyMQ8wDQYDVQQpEwZz
ZXJ2ZXIxJDAiBgkqhkiG9w0BCQEWFXBpbm95Z3JvdW5kQGdtYWlsLmNvbTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOJ4AEDK3oXTLWNUzDxJcpipdr0b
YpWqNh/rtoZL2qnAUHvAvz9v1Dgyua0zuBP7a7hBwZgFrD5JZD4bn48HuLW2fIZZ
vqOTMYy3d7hQpLEZOzSpIUqmJYNIYMsNHxNb1a/rKh1VQY12xQUNmHqa+CJYTBEB
meOzQAqdTMyLHoa/m2MmYRmGWoipmZNmDnSCMYOzf8zNVwPlW848l13IYsjolNha
6ag7vrqmsIVZ5BDTosTTTfuPqW6Yu7ZpnWPEAd9GGl3SJrcPPXQi/rsWdShD7Jzl
rdS2r0LrJnbGgym50FBEzfHRD2h7LYyGfyT8j00FbkeLfMAE4ejJl0y7/qcCAwEA
AaOCAYAwggF8MAkGA1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgZAMDQGCWCGSAGG
+EIBDQQnFiVFYXN5LVJTQSBHZW5lcmF0ZWQgU2VydmVyIENlcnRpZmljYXRlMB0G
A1UdDgQWBBTgxWfy9120ZbhxCl1YwBa1CdlztzCB0QYDVR0jBIHJMIHGgBQC8aEf
9OKz5hEIYpAtQpoxwISGyKGBoqSBnzCBnDELMAkGA1UEBhMCVVMxCzAJBgNVBAgT
AlBIMRAwDgYDVQQHEwdNYXluaWxhMQ4wDAYDVQQKEwVUb25kbzEUMBIGA1UECxML
UGlub3lHcm91bmQxETAPBgNVBAMTCFRvbmRvIENBMQ8wDQYDVQQpEwZzZXJ2ZXIx
JDAiBgkqhkiG9w0BCQEWFXBpbm95Z3JvdW5kQGdtYWlsLmNvbYIJAKyvksf/QCcw
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIFoDARBgNVHREECjAIggZz
ZXJ2ZXIwDQYJKoZIhvcNAQELBQADggEBADsZpSI0DntREo03bhAZWNihO6LF+GI7
Nx0GWvOmNb0PImF94vNUAKV7nKfiO+BvNaAdIwLH8CuKsFEkLYe2Xc6BSvIy3UKk
tfBNHqxfNlLJwLofxzxq8ojhFBuE51OE7ogVORAkvI1kymV1VQ19Cd2j0pQr1X5G
cnCRaQKmeVihTxsYwJpLlhaycKXNu78ztRp2UZOKyktFUL5SvSjPlH7ZhGyTQ7PQ
L6U+Mr0NRorRRi1k8FAvxn1UVIg/9QIXcW8cS80s1MD8ORW8RmI269D+/MLB9fsY
b3yRYQ4s4RcIRJ9m5NWZML/1Cpa2Ho/qxrtrtAyC7++FbnSUwgwrlN4=
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/server.key
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDieABAyt6F0y1j
VMw8SXKYqXa9G2KVqjYf67aGS9qpwFB7wL8/b9Q4MrmtM7gT+2u4QcGYBaw+SWQ+
G5+PB7i1tnyGWb6jkzGMt3e4UKSxGTs0qSFKpiWDSGDLDR8TW9Wv6yodVUGNdsUF
DZh6mvgiWEwRAZnjs0AKnUzMix6Gv5tjJmEZhlqIqZmTZg50gjGDs3/MzVcD5VvO
PJddyGLI6JTYWumoO766prCFWeQQ06LE0037j6lumLu2aZ1jxAHfRhpd0ia3Dz10
Iv67FnUoQ+yc5a3Utq9C6yZ2xoMpudBQRM3x0Q9oey2Mhn8k/I9NBW5Hi3zABOHo
yZdMu/6nAgMBAAECggEAH9fduT6NQWXrKN9ghE2ThnG1l2uFViQDzkM3e/Sof1vi
NTRp78KKpYhEYV03Ud/1Sog8b2LE0FFDfhQmQFdGmo5ZPg7aZmeo/O9DLzBvp9Mz
ZvktDDEGb0o7CfIDX5Z3GnBHkK5PNFPx6f76ZKrrnvCpaW6/M6wdoiByDwS0ux9s
Pr8ALFFKPgYwc5QNt/R0iFOYqQfSA3UrzdOolklbfQRB9+n5kBqQ69PlKd+JwhGy
tO07DysEmNGlMQoNw7pm6nDVwYO+KdmFcj23jTgcgsmvdqh6ucreFYWYn9pf6wGo
0HJ9E7J2BRXdfgZ26WdDicPONFCmuQBvsCnW+pVGiQKBgQD3Dv8W17ZtAZTwP1m3
uNRn2mYcI4+0MufXwaT3yqQ2G8NY5kTvEeqAO/+LubzOC231FAU+359YQHK/f1X0
NpmiGfOtu4iQxjGujBr1PndIIhJZAJYgbr9F6rMnRpcVfhTZO5e/5nr92mksMrK2
zzZLw0QObLw0nJqnL1hrmBBH0wKBgQDqqj1EVLfTizxf8BtN7SbQqwyFgirpGBOC
zJKORNQsDgYs949sWOsQz+q09NIhOkd1jlvE7GA5g/v6+UkWuN7ZGAhFnre3u9Aa
pn3xyqO9Sur6h2S17EUlRVYww7OITTquSsjZT6l5cKA6FRIuEm3PuBypuHLo3CAB
+rZXSDUdXQKBgQDbAvdNV6LHVTykEXTGMlpRSkF0tm2g7/Oox2gnpgMWWFw/Bbqc
OESqswVh5yChg25RcRMJXpHSWSef7RDUckaVde4X2ARDWv8V3evT9jElx9Z+AdAU
Jjj3kQyKR8CNc/ylanemzXnAagsL/FGDT4OxfANryia5eQ58ILOAhggAswKBgBEx
vB9/naCQeTIGY9nH4Ko1fktiCEbgDr3sw2hNPsajmGw/D3E+6qpmsankrmjk3kuM
zMiXEU3lj9cJ4QMbNKjvi9ueD5QU3OC3Bk9rK6g5DxKgTQ7PaxmaBQC5tjPshLo0
nJbfsWlGiVb4KEbb7tPjh6Yf77uENYwvlKC8l7e5AoGANeITeKJPjrzvHjx27Zdf
8brrZV1zbQZoeOWR6qj/0XSufNOnGK5KJXjNE8zKovmGoZjjspnQBzoTN5uJ1IoM
QpNYIm3S1oSDImrrNeRjIaUrVo3FAfu4vf3eKNqHLe9kUSriLU5DSu/Wfep3fFn1
nkd5vWo7A6vkZX/Iu6MzKDE=
-----END PRIVATE KEY-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAohzwXz9fsjw+G9Q14qINNOhZnTt/b30zzJYm4o2NIzAngM6E6GPm
N5USUt0grZw6h3VP9LyqQoGi/bHFz33YFG5lgDF8FAASEh07/leF7s0ohhK8pspC
JVD+mRatwBrIImXUpJvYI2pXKxtCOnDa2FFjAOHKixiAXqVcmJRwNaSklQcrpXdn
/09cr0rbFoovn+f1agly4FxYYs7P0XkvSHm3gVW/mhAUr1hvZlbBaWFSVUdgcVOi
FXQ/AVkvxYaO8pFI2Vh+CNMk7Vvi8d3DTayvoL2HTgFi+OIEbiiE/Nzryu+jDGc7
79FkBHWOa/7eD2nFrHScUJcwWiSevPQjQwIBAg==
-----END DH PARAMETERS-----
EOF

chmod 755 /etc/openvpn/server.conf
chmod 755 /etc/openvpn/server2.conf
chmod 755 /etc/openvpn/server3.conf
chmod 755 /etc/openvpn/login/connect.sh
chmod 755 /etc/openvpn/login/disconnect.sh
chmod 755 /etc/openvpn/login/config.sh
chmod 755 /etc/openvpn/login/auth_vpn
touch /var/www/html/stat/status.txt
touch /var/www/html/stat/udpstatus.txt
touch /var/www/html/stat/udpstatus2.txt
touch /var/www/html/stat/ipp.txt
chmod 755 /var/www/html/stat/*
echo -e "\e[1;32m Done Creating Openvpn Files  \033[0m"
sleep 2

echo -e "\033[01;31m Configure Sysctl \033[0m"
echo 'fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv4.icmp_echo_ignore_all = 1' >> /etc/sysctl.conf
echo '* soft nofile 512000
* hard nofile 512000' >> /etc/security/limits.conf
ulimit -n 512000

echo -e "\e[1;32m Done Configuring Sysctl  \033[0m"
sleep 2


echo -e "\033[01;31m Installing Stunnel \033[0m"
apt-get install stunnel4 -y > /dev/null 2>&1
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/bin/cat <<"EOM" > /etc/stunnel/stunnel.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqBptpzCvwPqN1nZHVlY2du2D/MXdiALyvPJDp1G+TKW7+FUd
IZnW8udc6IVJZ2RZUtN/Edzvis0b2XXB9t3o6jR2CShn0uqmdTS14BjsNyrXBZRk
8tWDZawClIWKOkSq76UpTKVOlXhq+Uk1eoT/zB5qlgaZv5L0ye3c/n/eJUzqjOgV
Rez+5XaEyI5A4+83NxALcz10coMP4Qr4Mcp2NALPbXj4KKiIguemiaD9tgp7iQqs
GxTxWhfvMsbYL7FcJpGwWpv5GcxeCyR+L2t/67hC7dAvB5NSnLTioD1e2qu0Zcd5
dhII8wr/pgC+7Y2GjTtITnHIogx3Q2LzCjF4owIDAQABAoIBAQCNfcEx6l7kdYAR
NXkSCHrLW1uu1PSD2MdrlhavrLQaW519hlaAw7YSuf6PkDCan/I3LuFTrbzJ/Z4l
SWK7YUj8aK+5QZMyCmOVX4p+Vzvrq1lUzvSxGFoCp+d8D3KrXMTr9P5wDuu4D6Uq
sh4bQ/ryWd+o62FZyF3V4SoT5Jicl2U1O3xC20nbZJMglXzuhQRaI3ZnuG4d0zHX
Eonp7wbcoKbDFJyrtSDhdwS9vylm5oo02+pgUZ1ELXglHw1ezuHekSOhIJBVdrER
3Ch9mJ0fqGQKofD1PaIGpFviBF3YJEskiVSpAAiZ5pmwFvzWxqAnlYi59nlHSvwB
tO7n51ChAoGBANw1uwTGhnU30Xgbx0KY+3J8kGHSJZeRjhZwt4646WxDT7EkAqjg
TovR80yNf7vVqwDt07j1Q5DNo7MVGbvyXwPaMsAXiYbBppaGRDQtp6UylIv+tmDo
DhYEbwQSQtGsdADjvtiBqt2tYdFW+omB88ZCfEuS7va5wcneP/Xq2UTrAoGBAMNs
snuSAzXhJaxyE6AvYFoFJxWW0H8FPhQ5g+xS+jBNpj9SbARzn7yZFRGXy2xzmbK+
wQA3IN40upIIy8ZiTIppvi/b/O8eaQqwQzsevzENMCKNGEjsrBpQ51wwzq1ix42Y
8Fn1AMsMaitC1YymvLOvtuIA29OBQ1a1pslrUI0pAoGAGGhcMktO2+8z6HwrudX7
CNWFq1H/mK0pcpNLxSX5uWY8jwXOxakXC6hZr0J/xfII4jF6JiYJNyOT4WWVVJ+o
qGSm+2Ogeq88J7L6HE5zJnxUuq+gx1zxMr+LDoh3n4Xd1btoi9bTeX6eOPXLDzK4
MmFsJXRDyFUOhbF8pWVCb8ECgYBfYEBnoKZieGS7md1MM3MR3CvsFHPjWjqnAj8J
aqHiSzNU+jPvpEKUeB3ZPT0xy+V6YDCvmzg2WoOn3BUf2D/E2cDReMskJLJdXhMh
2mqzVN1mL3hntuJz4YJY8xUbd/cuezLqpHFjp8Z1IKQ6hfHYvGxENukSe6bSvcsN
yItCqQKBgG/nF1FTFjM97x049sP7iAlxhRxg2Yi6qthvmmFo8xBnLO66CG9PEC3G
1MYWIzB6YtJG89NFFIGog/G2Cz95JjJDLDUOO41K/z1pBnArP54jvxx+iDuZlFMB
mWorw0zwnwbBhrQ3hH+YsQ5uI9eg7RN+8ZbmoXUweeUlzpsiaMaw
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIEHTCCAwWgAwIBAgIJAIciQafGgIDvMA0GCSqGSIb3DQEBBQUAMIGkMQswCQYD
VQQGEwJCRDEOMAwGA1UECAwFRGhha2ExDjAMBgNVBAcMBURoYWthMRgwFgYDVQQK
DA9BMlogU0VSVkVSUyBMVEQxFzAVBgNVBAsMDmEyenNlcnZlcnMuY29tMRswGQYD
VQQDDBJ3d3cuYTJ6c2VydmVycy5jb20xJTAjBgkqhkiG9w0BCQEWFnN1cHBvcnRA
YTJ6c2VydmVycy5jb20wHhcNMjAwNjI3MDQzODU5WhcNNDgwMjE2MDQzODU5WjCB
pDELMAkGA1UEBhMCQkQxDjAMBgNVBAgMBURoYWthMQ4wDAYDVQQHDAVEaGFrYTEY
MBYGA1UECgwPQTJaIFNFUlZFUlMgTFREMRcwFQYDVQQLDA5hMnpzZXJ2ZXJzLmNv
bTEbMBkGA1UEAwwSd3d3LmEyenNlcnZlcnMuY29tMSUwIwYJKoZIhvcNAQkBFhZz
dXBwb3J0QGEyenNlcnZlcnMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAqBptpzCvwPqN1nZHVlY2du2D/MXdiALyvPJDp1G+TKW7+FUdIZnW8udc
6IVJZ2RZUtN/Edzvis0b2XXB9t3o6jR2CShn0uqmdTS14BjsNyrXBZRk8tWDZawC
lIWKOkSq76UpTKVOlXhq+Uk1eoT/zB5qlgaZv5L0ye3c/n/eJUzqjOgVRez+5XaE
yI5A4+83NxALcz10coMP4Qr4Mcp2NALPbXj4KKiIguemiaD9tgp7iQqsGxTxWhfv
MsbYL7FcJpGwWpv5GcxeCyR+L2t/67hC7dAvB5NSnLTioD1e2qu0Zcd5dhII8wr/
pgC+7Y2GjTtITnHIogx3Q2LzCjF4owIDAQABo1AwTjAdBgNVHQ4EFgQUgKaZRa2J
NYxKkeTXnL1NQY5ueqowHwYDVR0jBBgwFoAUgKaZRa2JNYxKkeTXnL1NQY5ueqow
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAX0kciouCCPcK3Wq9UPUY
DrrkOD3VC469rMGZFxw9sWRO/ZYomiF391lbVJ1JYtRNQBF01YaxdSGDHYzpTfbg
OXiuMo/s97wP67yzXbmFU9pU9767jJVDKwQXzAYmK668lloRRCzv7berxNXTOm5c
xoa97gnLUiGMU4nQS2G4rAsF56ddk3WnuXxH/3hIVjSSIdq9eg4+fsDgxVnH2ehN
DLkRM+jNpiLRpm9txGOTnyFAikNGOboNSDYNx9J/uM5uoPzJDOQAoW+gV7pTut3b
I//hEv0+/RO5PEfXQkK25mpOcXgJNmxJ5UuUvm7vm5j72hzF5lT3MFYtIDwZ7Pte
+A==
-----END CERTIFICATE-----
EOM


echo 'cert=/etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no
[squid]
accept = 8000
connect = 127.0.0.1:8010

[SSH]
accept = 333
connect = 127.0.0.1:22

[openvpn]
accept = 587
connect = 127.0.0.1:1194'| sudo tee /etc/stunnel/stunnel.conf
echo -e "\e[1;32m Done Installing Stunnel  \033[0m"
sleep 2





#API Details
VPN_Owner='Tknetwork';
API_LINK='http://onlinevpn.shop/api/authentication';
API_KEY='Tknetwork';



sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4

cat <<EOF >/home/authentication.sh
#!/bin/bash
SHELL=/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
wget -O /home/active.sh "$API_LINK/active.php?key=$API_KEY"
sleep 5
wget -O /home/inactive.sh "$API_LINK/inactive.php?key=$API_KEY"
sleep 5
wget -O /home/deleted.sh "$API_LINK/deleted.php?key=$API_KEY"
sleep 15
bash /home/active.sh
sleep 15
bash /home/inactive.sh
sleep 15
bash /home/deleted.sh
EOF

echo -e "* *\t* * *\troot\tsudo bash /home/authentication.sh" >> "/etc/cron.d/account"

# DROPBEAR
systemctl enable dropbear
cat > /etc/default/dropbear <<EOF
NO_START=0
DROPBEAR_PORT=442
DROPBEAR_EXTRA_ARGS=
DROPBEAR_BANNER=""
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
EOF


wget -O /bin/badvpn-udpgw "https://www.dropbox.com/s/ugv8xks6g6xxkt9/badvpn-udpgw" 
chmod 777 /bin/badvpn-udpgw
wget -O /root/bad.sh "https://www.dropbox.com/s/s92tmm7lqaef0sx/bad.sh?dl=0"

#BADVPN 
screen -dmS udpvpn /bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 2000 --max-connections-for-client 50 -y

wget -O /root/proxydirect.py "http://onlinevpn.shop/script/ubuntu/openvpn/proxy derect.sh";python /root/proxydirect.py 8080 KRYPTOMIC &
wget -O /root/check.sh "http://onlinevpn.shop/script/ubuntu/openvpn/check.sh"

echo "*/10 * * * * bash /root/check.sh" | crontab -




crontab -r
echo "SHELL=/bin/bash
* * * * * /bin/bash /root/auto >/dev/null 2>&1" | crontab -


echo -e "\033[01;31m Configuring Iptables & Fail2ban \033[0m"
sudo add-apt-repository ppa:linrunner/tlp -y > /dev/null 2>&1
sudo apt-get update > /dev/null 2>&1
sudo apt-get install tlp tlp-rdw -y > /dev/null 2>&1
sudo tlp start > /dev/null 2>&1

update-rc.d squid3 enable
update-rc.d openvpn enable
update-rc.d apache2 enable
update-rc.d cron enable
update-rc.d stunnel4 enable
update-rc.d fail2ban enable
update-rc.d tlp enable

iptables -F; iptables -X; iptables -Z
iptables -t nat -A POSTROUTING -s 172.20.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.20.0.0/24 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -j SNAT --to-source "$(curl ipecho.net/plain)"
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -j SNAT --to-source "$(curl ipecho.net/plain)"
iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -j SNAT --to-source "$(curl ipecho.net/plain)"
iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -j SNAT --to-source "$(curl ipecho.net/plain)"
sysctl -p

sudo usermod -a -G www-data root
sudo chgrp -R www-data /var/www
sudo chmod -R g+w /var/www

touch /usr/local/sbin/reboot.sh
echo 'reboot
' > /usr/local/sbin/reboot.sh
touch /usr/local/sbin/ssl.sh
echo 'service stunnel4 start
' > /usr/local/sbin/ssl.sh
/bin/cat <<"EOM" >/usr/local/sbin/ram.sh
sudo sync; echo 3 > /proc/sys/vm/drop_caches
swapoff -a && swapon -a
echo '#' > /var/log/haproxy.log
echo "Ram Cleaned!"
EOM

chmod +x /usr/local/sbin/ram.sh
chmod +x /usr/local/sbin/reboot.sh
chmod +x /usr/local/sbin/ssl.sh

(crontab -l 2>/dev/null || true; echo "#
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 4 * * * /usr/local/sbin/reboot.sh
*/15 * * * * /usr/local/sbin/ssl.sh
* * * * * /usr/local/sbin/ram.sh") | crontab -
0 */12 * * * root /sbin/shutdown -r now


service cron restart

sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i 's/bantime  = 600/bantime  = 3600/g' /etc/fail2ban/jail.local
sed -i 's/maxretry = 10/maxretry = 3/g' /etc/fail2ban/jail.local
sed -i 's/destemail = '.*'/destemail = eric@gmail.com/g' /etc/fail2ban/jail.local

sudo timedatectl set-timezone Asia/Dhaka
timedatectl

sudo apt install debconf-utils -y > /dev/null 2>&1

echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get install iptables-persistent -y > /dev/null 2>&1

iptables-save > /etc/iptables/rules.v4 
ip6tables-save > /etc/iptables/rules.v6
echo -e "\e[1;32m Configuring Done \033[0m"
sleep 2

/bin/cat <<"EOM" >/var/www/html/index.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Tk@Network International</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<link rel="stylesheet" href="https://bootswatch.com/4/slate/bootstrap.min.css" media="screen">
<link href="https://fonts.googleapis.com/css?family=Press+Start+2P" rel="stylesheet">
<style>
    body {
     font-family: "Press Start 2P", cursive;    
    }
    .fn-color {
        color: #ff00ff;
        background-image: -webkit-linear-gradient(92deg, #f35626, #feab3a);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        -webkit-animation: hue 5s infinite linear;
    }

    @-webkit-keyframes hue {
      from {
        -webkit-filter: hue-rotate(0deg);
      }
      to {
        -webkit-filter: hue-rotate(-360deg);
      }
    }
</style>
</head>
<body>
<div class="container" style="padding-top: 50px">
<div class="jumbotron">
<h1 class="display-3 text-center fn-color">Tk@Network</h1>
<h4 class="text-center fn-color">Follow Us</h4>
<p class="text-center">https://web.facebook.com/ericson.hernandez1</p>
</div>
</div>
</body>
</html>
EOM

apt-get install squid -y
rm -f /etc/squid/squid.*
cat <<'SquidProxy' > /etc/squid/squid.conf
acl VPN dst IP-ADDRESS/32
http_access allow VPN
http_access deny all
http_port 0.0.0.0:8010
http_port 0.0.0.0:3128
acl bonv src 0.0.0.0/0.0.0.0
no_cache deny bonv
dns_nameservers 1.1.1.1 1.0.0.1
visible_hostname localhost
SquidProxy
sed -i "s|IP-ADDRESS|$MYIP|g" /etc/squid/squid.conf

echo -e "\033[01;31m Starting Services \033[0m"
service openvpn start
service squid start
service apache2 start
service fail2ban start
service stunnel4 start

sed -i 's/#ForwardToWall=yes/ForwardToWall=no/g' /etc/systemd/journald.conf

sudo apt-get autoremove -y > /dev/null 2>&1
sudo apt-get clean > /dev/null 2>&1
history -c
cd /root || exit
rm -f /root/openvpn.sh
echo -e "\e[1;32m Installing Done \033[0m"
echo 'root:@@Alaminbd257' | sudo chpasswd
reboot
