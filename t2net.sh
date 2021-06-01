apt-get update -y

DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -q -y -u  -o Dpkg::Options::="--force-confdef" --allow-downgrades --allow-remove-essential --allow-change-held-packages --allow-unauthenticated
apt-get install screen sudo mysql-client nano fail2ban unzip apache2 build-essential curl build-essential libwrap0-dev libpam0g-dev libdbus-1-dev libreadline-dev libnl-route-3-dev libprotobuf-c0-dev libpcl1-dev libopts25-dev autogen libgnutls28-dev libseccomp-dev libhttp-parser-dev php libapache2-mod-php -y
apt-get install openvpn easy-rsa -y
sed -i 's/Listen 80/Listen 81/g' /etc/apache2/ports.conf
service apache2 restart
mkdir -p /etc/openvpn/easy-rsa/keys
mkdir -p /etc/openvpn/login
mkdir -p /etc/openvpn/radius
mkdir -p /var/www/html/stat
touch /etc/openvpn/server.conf
touch /etc/openvpn/server2.conf

/bin/cat <<"EOM" >/etc/openvpn/login/auth_vpn
#!/bin/bash
username=`head -n1 $1 | tail -1`   
password=`head -n2 $1 | tail -1`

HOST='64.20.61.229'
USER='vpnnetcl_t2vpn'
PASS='&HQi}!&GH}_M'
DB='vpnnetcl_t2vpn'

Query="SELECT user_name FROM users WHERE user_name='$username' AND user_encryptedPass=md5('$password') AND is_freeze='0' AND user_duration > 0"
user_name=`mysql -u $USER -p$PASS -D $DB -h $HOST -sN -e "$Query"`
[ "$user_name" != '' ] && [ "$user_name" = "$username" ] && echo "user : $username" && echo 'authentication ok.' && exit 0 || echo 'authentication failed.'; exit 1
EOM
chmod +x /etc/openvpn/login/auth_vpn

echo 'mode server 
tls-server 
port 1194
proto tcp 
dev tun
keepalive 1 180
resolv-retry infinite 
max-clients 1000
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh /etc/openvpn/easy-rsa/keys/dh2048.pem 
client-cert-not-required 
username-as-common-name 
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-file # 
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
script-security 2
up /etc/openvpn/update-resolv-conf                                                                                      
down /etc/openvpn/update-resolv-conf
status /var/www/html/stat/udpstatus2.txt
ifconfig-pool-persist /var/www/html/stat/ipp.txt' > /etc/openvpn/server.conf

echo 'mode server 
tls-server 
port 55
proto udp 
dev tun
keepalive 1 180
resolv-retry infinite 
max-clients 1000
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh /etc/openvpn/easy-rsa/keys/dh2048.pem 
client-cert-not-required 
username-as-common-name 
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-file # 
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
script-security 2
up /etc/openvpn/update-resolv-conf                                                                                      
down /etc/openvpn/update-resolv-conf
status /var/www/html/stat/udpstatus.txt
ifconfig-pool-persist /var/www/html/stat/ipp.txt' > /etc/openvpn/server2.conf

cat << EOF > /etc/openvpn/easy-rsa/keys/ca.crt
-----BEGIN CERTIFICATE-----
MIIFDDCCA/SgAwIBAgIJAPVaxZZ9crxTMA0GCSqGSIb3DQEBCwUAMIG0MQswCQYD
VQQGEwJCRDEOMAwGA1UECBMFRGhha2ExDjAMBgNVBAcTBURoYWthMRgwFgYDVQQK
Ew9BMlogU0VSVkVSUyBMVEQxFzAVBgNVBAsTDmEyenNlcnZlcnMuY29tMRcwFQYD
VQQDEw5hMnpzZXJ2ZXJzLmNvbTESMBAGA1UEKRMJQkRFYXN5UlNBMSUwIwYJKoZI
hvcNAQkBFhZzdXBwb3J0QGEyenNlcnZlcnMuY29tMB4XDTIwMDYyNjA1NDM0NloX
DTMwMDYyNDA1NDM0NlowgbQxCzAJBgNVBAYTAkJEMQ4wDAYDVQQIEwVEaGFrYTEO
MAwGA1UEBxMFRGhha2ExGDAWBgNVBAoTD0EyWiBTRVJWRVJTIExURDEXMBUGA1UE
CxMOYTJ6c2VydmVycy5jb20xFzAVBgNVBAMTDmEyenNlcnZlcnMuY29tMRIwEAYD
VQQpEwlCREVhc3lSU0ExJTAjBgkqhkiG9w0BCQEWFnN1cHBvcnRAYTJ6c2VydmVy
cy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCRUlPZAvENlXG
5r1EmX2BGwECWVFW9nrnXxIfx0Ia+04tlA17TGuRmRhH3irQAXjbXr8TBkx9Ttqy
eMdzUPzlTY8LZnVg/pwOkdxpODSB5/Icy0527d4492wbLp1XJdXJky/zEbW0jZF2
K6nXVtBIezFni/jj4xoWCnaWAGaM1jgysa0bsxCoHCJ6pG5Ih+Q3XX03FSBGbHtq
TebdzY5LzInckLNLA5qk39qo3PZzSPC6u2voZxqK0/Wrwa9nHPlCjX5nlOn7A+/8
IwHrD1qM0mja7AGW6bVSC+tnc9+YYz2p1bVY9yPS9E7OoWRN64Gz5AhlZjLLREuT
zoAZd2EnAgMBAAGjggEdMIIBGTAdBgNVHQ4EFgQU7YzIByeyPY8NFjG0ZGQb3cj0
s/QwgekGA1UdIwSB4TCB3oAU7YzIByeyPY8NFjG0ZGQb3cj0s/ShgbqkgbcwgbQx
CzAJBgNVBAYTAkJEMQ4wDAYDVQQIEwVEaGFrYTEOMAwGA1UEBxMFRGhha2ExGDAW
BgNVBAoTD0EyWiBTRVJWRVJTIExURDEXMBUGA1UECxMOYTJ6c2VydmVycy5jb20x
FzAVBgNVBAMTDmEyenNlcnZlcnMuY29tMRIwEAYDVQQpEwlCREVhc3lSU0ExJTAj
BgkqhkiG9w0BCQEWFnN1cHBvcnRAYTJ6c2VydmVycy5jb22CCQD1WsWWfXK8UzAM
BgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCe09DqQ/yhLffM5KCdd3UN
W41KF32do7WVYvzKAdlXPhByuPFaBXtOadCkclRg/opj2k6RBz4hmQCCUk4AxL/o
qG/FOseB33eWAs8GwuuocjRoUiHk6gMTNUcdGaJQASzLHU60WBIUK5enFf2m359p
qOhty1KzLIC5rgnVAnSglC7i/3hpO+KZKO8qoMVeMNE9ppOEnuQ3gCwnSdjjxFNQ
SgjBWmj9lzKK4js9D26CgQQiwdW+95WJqoqpO5y6Y0pVqx3xx3jsE1JokITW8zcd
at3rXO5wG4s+N1cS/b4eRRF1wQnYZIOhsyprYYWS6fOptt1fdq3iVhYhBEUXSfFm
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=BD, ST=Dhaka, L=Dhaka, O=A2Z SERVERS LTD, OU=a2zservers.com, CN=a2zservers.com/name=BDEasyRSA/emailAddress=support@a2zservers.com
        Validity
            Not Before: Jun 26 05:45:53 2020 GMT
            Not After : Jun 24 05:45:53 2030 GMT
        Subject: C=BD, ST=Dhaka, L=Dhaka, O=A2Z Servers Ltd, OU=A2Z Servers, CN=a2zservers.com/name=BDEasyRSA/emailAddress=support@a2zservers.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ea:39:b8:b8:ea:cc:27:d4:97:0f:08:74:52:f6:
                    25:19:95:e7:39:2d:c9:d5:1b:3f:10:0e:b2:94:29:
                    c2:cc:ee:6c:a6:49:15:06:e5:24:35:41:47:26:41:
                    ae:25:f4:77:a8:59:93:84:de:f8:05:a8:93:5d:06:
                    21:09:7c:b6:0d:d2:a2:68:94:fd:0a:f6:71:cd:b1:
                    65:a0:02:5a:0c:0b:33:0a:5c:06:82:c4:1f:de:70:
                    cd:66:c6:82:27:e1:e4:3c:e4:e4:8d:e7:c8:7c:d6:
                    68:2f:1c:d8:9c:52:02:a2:e2:0d:03:91:3b:a5:25:
                    3f:dd:e5:07:fb:cc:90:0d:0a:ae:9d:de:97:1a:0e:
                    5f:eb:c2:e8:8c:2b:2e:31:d6:f6:78:27:11:5d:19:
                    40:7a:cf:2d:3d:84:fc:e6:a4:74:50:ff:c0:da:05:
                    a1:10:ec:bc:97:5f:5e:04:ac:b1:a8:ac:97:e8:9e:
                    5d:51:e7:67:6f:b7:52:94:08:77:2f:ed:9d:69:f0:
                    a0:10:8d:b6:5e:f1:56:37:5d:38:58:df:6e:8d:21:
                    76:18:d1:de:cb:96:70:07:04:0b:a3:ca:bb:c2:b4:
                    51:50:44:7c:34:c9:95:9a:2c:01:62:aa:7a:80:01:
                    e7:69:22:c8:6f:f4:aa:6f:76:2b:44:9d:91:71:bc:
                    e0:39
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                Easy-RSA Generated Server Certificate
            X509v3 Subject Key Identifier: 
                E4:75:2E:ED:FD:F3:AB:7F:31:FB:B0:51:03:71:DE:FA:23:E5:2B:3A
            X509v3 Authority Key Identifier: 
                keyid:ED:8C:C8:07:27:B2:3D:8F:0D:16:31:B4:64:64:1B:DD:C8:F4:B3:F4
                DirName:/C=BD/ST=Dhaka/L=Dhaka/O=A2Z SERVERS LTD/OU=a2zservers.com/CN=a2zservers.com/name=BDEasyRSA/emailAddress=support@a2zservers.com
                serial:F5:5A:C5:96:7D:72:BC:53

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
    Signature Algorithm: sha256WithRSAEncryption
         81:56:cf:3e:d4:5b:6a:c8:2f:37:7c:31:ba:ae:2e:0c:20:4a:
         8a:bd:b7:35:cc:bc:47:c0:2d:b8:8c:8d:7a:9a:f2:ab:28:3d:
         02:7a:d6:06:b8:77:71:b5:a2:40:a2:6f:1a:34:02:40:a1:d5:
         e6:19:08:e7:08:fd:38:0b:fa:fc:b7:c7:22:9a:f3:f7:88:56:
         a4:69:a2:df:67:4a:80:90:d8:86:b3:db:43:3b:cb:37:86:f4:
         d9:31:7e:23:5d:9f:a3:82:14:df:eb:ae:7e:8d:76:a2:c8:29:
         ae:2e:f3:e9:db:1d:33:34:28:bb:78:a8:97:af:46:bf:a1:1d:
         ab:4f:2b:cf:bb:6c:64:24:13:a0:6d:4b:44:9d:05:92:fe:03:
         f7:29:be:f5:f6:fd:62:cc:11:e9:e4:f8:6c:88:43:0a:04:fd:
         0e:82:a2:bb:98:87:77:55:27:ae:12:30:3b:0a:37:52:fd:79:
         e1:00:00:7f:7f:51:1b:2f:b3:5b:f3:7d:0a:78:55:22:3b:cb:
         9a:ea:f6:f7:4e:f1:66:0c:b1:3e:5d:1e:45:3b:c5:03:3b:ae:
         8a:bc:4f:8e:40:da:a3:b4:54:f6:f7:ef:04:fe:95:38:ca:de:
         72:10:8a:f9:dd:a2:78:f0:a0:ae:48:84:f9:de:69:4d:05:66:
         fb:d2:bc:fd
-----BEGIN CERTIFICATE-----
MIIFaTCCBFGgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBtDELMAkGA1UEBhMCQkQx
DjAMBgNVBAgTBURoYWthMQ4wDAYDVQQHEwVEaGFrYTEYMBYGA1UEChMPQTJaIFNF
UlZFUlMgTFREMRcwFQYDVQQLEw5hMnpzZXJ2ZXJzLmNvbTEXMBUGA1UEAxMOYTJ6
c2VydmVycy5jb20xEjAQBgNVBCkTCUJERWFzeVJTQTElMCMGCSqGSIb3DQEJARYW
c3VwcG9ydEBhMnpzZXJ2ZXJzLmNvbTAeFw0yMDA2MjYwNTQ1NTNaFw0zMDA2MjQw
NTQ1NTNaMIGxMQswCQYDVQQGEwJCRDEOMAwGA1UECBMFRGhha2ExDjAMBgNVBAcT
BURoYWthMRgwFgYDVQQKEw9BMlogU2VydmVycyBMdGQxFDASBgNVBAsTC0EyWiBT
ZXJ2ZXJzMRcwFQYDVQQDEw5hMnpzZXJ2ZXJzLmNvbTESMBAGA1UEKRMJQkRFYXN5
UlNBMSUwIwYJKoZIhvcNAQkBFhZzdXBwb3J0QGEyenNlcnZlcnMuY29tMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6jm4uOrMJ9SXDwh0UvYlGZXnOS3J
1Rs/EA6ylCnCzO5spkkVBuUkNUFHJkGuJfR3qFmThN74BaiTXQYhCXy2DdKiaJT9
CvZxzbFloAJaDAszClwGgsQf3nDNZsaCJ+HkPOTkjefIfNZoLxzYnFICouINA5E7
pSU/3eUH+8yQDQqund6XGg5f68LojCsuMdb2eCcRXRlAes8tPYT85qR0UP/A2gWh
EOy8l19eBKyxqKyX6J5dUednb7dSlAh3L+2dafCgEI22XvFWN104WN9ujSF2GNHe
y5ZwBwQLo8q7wrRRUER8NMmVmiwBYqp6gAHnaSLIb/Sqb3YrRJ2RcbzgOQIDAQAB
o4IBhTCCAYEwCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBkAwNAYJYIZIAYb4
QgENBCcWJUVhc3ktUlNBIEdlbmVyYXRlZCBTZXJ2ZXIgQ2VydGlmaWNhdGUwHQYD
VR0OBBYEFOR1Lu3986t/MfuwUQNx3voj5Ss6MIHpBgNVHSMEgeEwgd6AFO2MyAcn
sj2PDRYxtGRkG93I9LP0oYG6pIG3MIG0MQswCQYDVQQGEwJCRDEOMAwGA1UECBMF
RGhha2ExDjAMBgNVBAcTBURoYWthMRgwFgYDVQQKEw9BMlogU0VSVkVSUyBMVEQx
FzAVBgNVBAsTDmEyenNlcnZlcnMuY29tMRcwFQYDVQQDEw5hMnpzZXJ2ZXJzLmNv
bTESMBAGA1UEKRMJQkRFYXN5UlNBMSUwIwYJKoZIhvcNAQkBFhZzdXBwb3J0QGEy
enNlcnZlcnMuY29tggkA9VrFln1yvFMwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYD
VR0PBAQDAgWgMA0GCSqGSIb3DQEBCwUAA4IBAQCBVs8+1FtqyC83fDG6ri4MIEqK
vbc1zLxHwC24jI16mvKrKD0CetYGuHdxtaJAom8aNAJAodXmGQjnCP04C/r8t8ci
mvP3iFakaaLfZ0qAkNiGs9tDO8s3hvTZMX4jXZ+jghTf665+jXaiyCmuLvPp2x0z
NCi7eKiXr0a/oR2rTyvPu2xkJBOgbUtEnQWS/gP3Kb719v1izBHp5PhsiEMKBP0O
gqK7mId3VSeuEjA7CjdS/XnhAAB/f1EbL7Nb830KeFUiO8ua6vb3TvFmDLE+XR5F
O8UDO66KvE+OQNqjtFT29+8E/pU4yt5yEIr53aJ48KCuSIT53mlNBWb70rz9
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/server.key
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDqObi46swn1JcP
CHRS9iUZlec5LcnVGz8QDrKUKcLM7mymSRUG5SQ1QUcmQa4l9HeoWZOE3vgFqJNd
BiEJfLYN0qJolP0K9nHNsWWgAloMCzMKXAaCxB/ecM1mxoIn4eQ85OSN58h81mgv
HNicUgKi4g0DkTulJT/d5Qf7zJANCq6d3pcaDl/rwuiMKy4x1vZ4JxFdGUB6zy09
hPzmpHRQ/8DaBaEQ7LyXX14ErLGorJfonl1R52dvt1KUCHcv7Z1p8KAQjbZe8VY3
XThY326NIXYY0d7LlnAHBAujyrvCtFFQRHw0yZWaLAFiqnqAAedpIshv9KpvditE
nZFxvOA5AgMBAAECggEBAMltalZcVcXLJT1gX+kYlT8zku2xWulRzSHaAek5ILVs
NTOrldGgLUs/IBjeUw2A94Znwl16AoGbP1+4baDjBw1MHy8hMZvD5IqoDGVWoGnL
F9HI4jCCyYVaLMo93KC/urBDh+ohcmEpYd9iR0XnoSzCib6Pn2OebRY+aGc6vIb5
C4gFjTZ8K+zSlTpd5Jx/B7wN4/IDuQxZIDkhNfqUj6OBnMIW/KvIUKGKmV0r4oXL
dacqoj5jbcRLl+SPqvMDcDqa2c37qWgctfalc8WQgooPBDkgMy38bZYsaTsa8k11
APdxIAYJaI8Yjy6fSZbuIp2SXfSLFhL+ofUSA1Xp+6ECgYEA+OChC1xj5rHvfUdQ
TyWSEywrD3HkYc12MEUWLF20aXF8lSYzuWRuOaz8DM45tMq0WkTFvQ0wd+xpEQfC
/9ZwQ0B/gb2P4T8iJFbjKDzgCleNfrAO6jz2h3qEKee6lC+0CX+37L4HFuPVqyDQ
OXfQZbIgbCUUCHDNi8d7rHclfPsCgYEA8O2/Gk/rXKjq2PyZ52UP7KhwSd48RNKM
NChIhMDZnKj//W1z8OQa0RHfXIPJ33ZOmaKunPT//foD48uuz9HrqLuwCRlfCfqJ
CQSUwp+YAoWDn0oSg/2jdAm16ziS6O0MpH4EL9zmHMeOaf4NmTIXlz8SXpYzeJ1c
ZmvtM+er6VsCgYEAioh/HFPRSBjDtnh7u5KuPP3Y+j/rYIV9xGCwdwGx6v/A2UTq
hcfhkzk3E+m3NWuf+J9PcmxlDlwKH/CyGrbCxqygTRe3fyolVxUGXN+F1jvmBx75
LmnA0Kjh6HGU6eejz6XIO3+LcrJfvWIGhfarifAdHBWHkSs5PxVLQjUQKQECgYEA
5IG5dO1D37heNbsvBWa2+dCv33+mTegcDgP+89otCwbG9Mhw5JKUVKLM5GQifY0p
81F2p2s/uNT+B3nRrU3+YyTQS3EC0OYMPr9XkFfpxsp3EgchFIrmElJ7dkNMIxth
mEnlErhCkB09F45bu2blNRAfDhMLcmRdlM7cRRR/2m0CgYBkOWtF+/+Wm5YJRpWo
K3lKVbcq9S24X3KcDUXg5s/Ijc8nzK1/MrMxJs4N5YPoD9UQhK+qVQYOhrgl5MFH
zP8bbWF17rlhP6BiqSnlF/DzSrgZAfySDkPIe/VkvrpYLqORuSzYP6jXRfz7Lpp8
7lVnzaO20Qkcj4RYWor59BE1LQ==
-----END PRIVATE KEY-----
EOF

cat << EOF > /etc/openvpn/easy-rsa/keys/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA1HeLrJUhIRQIGcVoMns4SvouSaPJ4xXC0Rsfq0ChoX3E2jtCtCrK
OT+0MFj3XY9RdhhqGVsPujE2B0bhqgN/xJk0+qHJPOt9HJA+yJ2dQmApQ587khyr
UgzcfPQWuu1djQZWdZjU60QKPSW20sYc5haVrJL3X5wbLBn/TymNwIFsve1Pevc3
lk1ZZMV0eHoPt3jF8KwqwD3mxLqVBS8vmfVXGdmN+isj/ElNIH5IWRvFCKwRBe8e
6hul1tMErmuk+XOV/bXeZaiUMAH4xJuK2Yk6ddEOPtVOLG35CnhcoYKGHFxacb5k
Pxt4S4N3wjL2n0bU0DDi/8MDLjtZDjuTOwIBAg==
-----END DH PARAMETERS-----
EOF

chmod 755 /etc/openvpn/server.conf
chmod 755 /etc/openvpn/server2.conf
chmod 755 /etc/openvpn/login/auth_vpn
touch /var/www/html/stat/status.txt
touch /var/www/html/stat/udpstatus.txt
touch /var/www/html/stat/udpstatus2.txt
touch /var/www/html/stat/ipp.txt
chmod 755 /var/www/html/stat/*


sudo touch /etc/apt/sources.list.d/trusty_sources.list
echo "deb http://us.archive.ubuntu.com/ubuntu/ trusty main universe" | sudo tee --append /etc/apt/sources.list.d/trusty_sources.list > /dev/null
sudo apt update -y

sudo apt install -y squid3=3.3.8-1ubuntu6 squid=3.3.8-1ubuntu6 squid3-common=3.3.8-1ubuntu6
/bin/cat <<"EOM" >/etc/init.d/squid3
#! /bin/sh
#
# squid		Startup script for the SQUID HTTP proxy-cache.
#
# Version:	@(#)squid.rc  1.0  07-Jul-2006  luigi@debian.org
#
### BEGIN INIT INFO
# Provides:          squid
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Should-Start:      $named
# Should-Stop:       $named
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Squid HTTP Proxy version 3.x
### END INIT INFO

NAME=squid3
DESC="Squid HTTP Proxy"
DAEMON=/usr/sbin/squid3
PIDFILE=/var/run/$NAME.pid
CONFIG=/etc/squid3/squid.conf
SQUID_ARGS="-YC -f $CONFIG"

[ ! -f /etc/default/squid ] || . /etc/default/squid

. /lib/lsb/init-functions

PATH=/bin:/usr/bin:/sbin:/usr/sbin

[ -x $DAEMON ] || exit 0

ulimit -n 65535

find_cache_dir () {
	w=" 	" # space tab
        res=`$DAEMON -k parse -f $CONFIG 2>&1 |
		grep "Processing:" |
		sed s/.*Processing:\ // |
		sed -ne '
			s/^['"$w"']*'$1'['"$w"']\+[^'"$w"']\+['"$w"']\+\([^'"$w"']\+\).*$/\1/p;
			t end;
			d;
			:end q'`
        [ -n "$res" ] || res=$2
        echo "$res"
}

grepconf () {
	w=" 	" # space tab
        res=`$DAEMON -k parse -f $CONFIG 2>&1 |
		grep "Processing:" |
		sed s/.*Processing:\ // |
		sed -ne '
			s/^['"$w"']*'$1'['"$w"']\+\([^'"$w"']\+\).*$/\1/p;
			t end;
			d;
			:end q'`
	[ -n "$res" ] || res=$2
	echo "$res"
}

create_run_dir () {
	run_dir=/var/run/squid3
	usr=`grepconf cache_effective_user proxy`
	grp=`grepconf cache_effective_group proxy`

	if [ "$(dpkg-statoverride --list $run_dir)" = "" ] &&
	   [ ! -e $run_dir ] ; then
		mkdir -p $run_dir
	  	chown $usr:$grp $run_dir
		[ -x /sbin/restorecon ] && restorecon $run_dir
	fi
}

start () {
	cache_dir=`find_cache_dir cache_dir`
	cache_type=`grepconf cache_dir`
	run_dir=/var/run/squid3

	#
	# Create run dir (needed for several workers on SMP)
	#
	create_run_dir

	#
	# Create spool dirs if they don't exist.
	#
	if test -d "$cache_dir" -a ! -d "$cache_dir/00"
	then
		log_warning_msg "Creating $DESC cache structure"
		$DAEMON -z -f $CONFIG
		[ -x /sbin/restorecon ] && restorecon -R $cache_dir
	fi

	umask 027
	ulimit -n 65535
	cd $run_dir
	start-stop-daemon --quiet --start \
		--pidfile $PIDFILE \
		--exec $DAEMON -- $SQUID_ARGS < /dev/null
	return $?
}

stop () {
	PID=`cat $PIDFILE 2>/dev/null`
	start-stop-daemon --stop --quiet --pidfile $PIDFILE --exec $DAEMON
	#
	#	Now we have to wait until squid has _really_ stopped.
	#
	sleep 2
	if test -n "$PID" && kill -0 $PID 2>/dev/null
	then
		log_action_begin_msg " Waiting"
		cnt=0
		while kill -0 $PID 2>/dev/null
		do
			cnt=`expr $cnt + 1`
			if [ $cnt -gt 24 ]
			then
				log_action_end_msg 1
				return 1
			fi
			sleep 5
			log_action_cont_msg ""
		done
		log_action_end_msg 0
		return 0
	else
		return 0
	fi
}

cfg_pidfile=`grepconf pid_filename`
if test "${cfg_pidfile:-none}" != "none" -a "$cfg_pidfile" != "$PIDFILE"
then
	log_warning_msg "squid.conf pid_filename overrides init script"
	PIDFILE="$cfg_pidfile"
fi

case "$1" in
    start)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_daemon_msg "Starting $DESC" "$NAME"
		if start ; then
			log_end_msg $?
		else
			log_end_msg $?
		fi
	fi
	;;
    stop)
	log_daemon_msg "Stopping $DESC" "$NAME"
	if stop ; then
		log_end_msg $?
	else
		log_end_msg $?
	fi
	;;
    reload|force-reload)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_action_msg "Reloading $DESC configuration files"
	  	start-stop-daemon --stop --signal 1 \
			--pidfile $PIDFILE --quiet --exec $DAEMON
		log_action_end_msg 0
	fi
	;;
    restart)
	res=`$DAEMON -k parse -f $CONFIG 2>&1 | grep -o "FATAL: .*"`
	if test -n "$res";
	then
		log_failure_msg "$res"
		exit 3
	else
		log_daemon_msg "Restarting $DESC" "$NAME"
		stop
		if start ; then
			log_end_msg $?
		else
			log_end_msg $?
		fi
	fi
	;;
    status)
	status_of_proc -p $PIDFILE $DAEMON $NAME && exit 0 || exit 3
	;;
    *)
	echo "Usage: /etc/init.d/$NAME {start|stop|reload|force-reload|restart|status}"
	exit 3
	;;
esac

exit 0
EOM

sudo chmod +x /etc/init.d/squid3
sudo update-rc.d squid3 defaults

echo "http_port 8080
acl to_vpn dst `curl ipinfo.io/ip`
http_access allow to_vpn 
via off
forwarded_for off
request_header_access Allow allow all
request_header_access Authorization allow all
request_header_access WWW-Authenticate allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control allow all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title allow all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access User-Agent allow all
request_header_access Cookie allow all
request_header_access All deny all 
http_access deny all"| sudo tee /etc/squid3/squid.conf

apt-get install stunnel4 -y
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/bin/cat <<"EOM" > /etc/stunnel/stunnel.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyN+jQb8vvS1jwbQSXAP9H0alRxuXuijhIp3u1gePGBsGLGg8
CWQrdhbB40W7Ov2xzg4KyiRwLgcfnOP2tHvtsN7BzC8DWrqqZsNyENDyIs3sX5oc
+JGLQZJiv2QSAP3N/4/UAAswUnGRW1TzQFXISSVeiScBsB96LoVLiPdA1e4Hhjkb
vggLOHHTcXqc1BBzIt9eg672O+yiILsOFuYPGh3TBwVZ0DvKYZocEsJ/RExOuAID
x0+THlpyO3PZhIo3EN5BVCmBcsUboByH9/Lsh+15tJqpvM8uiB9pjxlWUiRNiHjm
J5+pOWX4FpGlgrJUYSSsUUddXmPVWAj1BeQ2GwIDAQABAoIBAH7ISC5zERqBz3iu
wve4vMZEvISI8dbZfl9u9xO3aaV5SQg2Mc5rntLFwlJD7Mxq2xKG4mB7ZyJl9Jn9
d/SqU3dS4VaSRbe6IVsC+LeMaYd2GT6t8qMgmZglYJYT/xkJGD+488GjTjh63Zeb
onx0qBkisOw35mTXOTKrhuVHyXA70dD1an0fXi6tiNkIT4AVwLgqJuFxE0seePlN
Y35jZF4JvX8hOvkSshkzxNWSIs2LOOCJL7dH90FYvUYA/kvW+64O7pouA/p/VkYD
rO0fYgJmureiUZfwEVJKfnBgdhIbStA3lRxDzDmxr1BBVFaraSZ+12/jQVEXOaRb
ErovK6ECgYEA5nV12egMRn3l3MItWmcURIDtTU8cy3WreP2zTzx9RZDs3Rw2HEbR
0jyLzJOHfyFdyGrZtbUAa/LoOKT2YvPKQ2P4k4ZFbYcnl7cgAL28CrpZgNZXoEaL
sMf6Qp6PG+VUSFoFcOi/GM2c4ZypVOR5MwGbfpJ4fusekxQiTijWs4cCgYEA3yLK
Kt8bXHgg7B92mTFEKsiYrgk5SgPcYQ/HxYOMS3hrI8J3JWkMOWCCAbS1nSPPd0BY
jXGL/LSRmWA8bX/objwq8Q8YDTuuDCIPsh/SoFZsdHWc0ZlOv1BsWGijJGa21n64
Ja5r3LWSH6YLCy2PmoQzBDaCtmr/rZWXPaS4tc0CgYEAre9jJjab5SwqK6amQj/g
LR+9eobGLc0+wM+B4MC/r5yFGRCsykStIeaugJWsQ0g0lwoGDL1ydwbbO71NdDuZ
oak3OGizx8mlGT2OOuD4poQk/zdG5WG5FpCoElXHnv9D0GOZDbGsYRT2XdU2fCsA
Sn3hFPOJXAkqh0k/5wutl8sCgYEA2aXAluK6eI7AZjEmaLTSbfzuWEus8tIjQxW2
YaU30mGp9952gyoc/1ZwWSOgRp+ofQRpm8XWqu6iWn2xU4mA+Q19QVbcugOteC49
Kxy5QSYrcclK5nNoiVnz5KRkBVyfGUfPbQneMhF1b6NxgDy3pxst+/0DsNVbgUC5
niou9T0CgYEAkTXYooaf7JTAMlu/wLunkT0ZWKL/bU4ZgOFVFnF2gdfWJnHTMSu5
PtxyjisZJNbON6xW0pIjcTuUQCIpL0LoZ7qd5zi5QqISb+eKzK8ENMxgnV7MEx78
lufFKJYrjhC8j9pwY5pAR5uw2HKMS34IqLXct6NypoEYsJ48YDfA0Qw=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIEATCCAumgAwIBAgIJAPDuiksIWVs2MA0GCSqGSIb3DQEBCwUAMIGWMQswCQYD
VQQGEwJQSDESMBAGA1UECAwJU1RST05HVlBOMRIwEAYDVQQHDAlTVFJPTkdWUE4x
EjAQBgNVBAoMCVNUUk9OR1ZQTjESMBAGA1UECwwJU1RST05HVlBOMRIwEAYDVQQD
DAlTVFJPTkdWUE4xIzAhBgkqhkiG9w0BCQEWFHN0cm9uZy12cG5AZ21haWwuY29t
MB4XDTE4MDcwMzA1MTM0MVoXDTIxMDcwMjA1MTM0MVowgZYxCzAJBgNVBAYTAlBI
MRIwEAYDVQQIDAlTVFJPTkdWUE4xEjAQBgNVBAcMCVNUUk9OR1ZQTjESMBAGA1UE
CgwJU1RST05HVlBOMRIwEAYDVQQLDAlTVFJPTkdWUE4xEjAQBgNVBAMMCVNUUk9O
R1ZQTjEjMCEGCSqGSIb3DQEJARYUc3Ryb25nLXZwbkBnbWFpbC5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDI36NBvy+9LWPBtBJcA/0fRqVHG5e6
KOEine7WB48YGwYsaDwJZCt2FsHjRbs6/bHODgrKJHAuBx+c4/a0e+2w3sHMLwNa
uqpmw3IQ0PIizexfmhz4kYtBkmK/ZBIA/c3/j9QACzBScZFbVPNAVchJJV6JJwGw
H3ouhUuI90DV7geGORu+CAs4cdNxepzUEHMi316DrvY77KIguw4W5g8aHdMHBVnQ
O8phmhwSwn9ETE64AgPHT5MeWnI7c9mEijcQ3kFUKYFyxRugHIf38uyH7Xm0mqm8
zy6IH2mPGVZSJE2IeOYnn6k5ZfgWkaWCslRhJKxRR11eY9VYCPUF5DYbAgMBAAGj
UDBOMB0GA1UdDgQWBBTxI2YSnxnuDpwgxKOUgglmgiH/vDAfBgNVHSMEGDAWgBTx
I2YSnxnuDpwgxKOUgglmgiH/vDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQC30dcIPWlFfBEK/vNzG1Dx+BWkHCfd2GfmVc+VYSpmiTox13jKBOyEdQs4
xxB7HiESKkpAjQ0YC3mjE6F53NjK0VqdfzXhopg9i/pQJiaX0KTTcWIelsJNg2aM
s8GZ0nWSytcAqAV6oCnn+eOT/IqnO4ihgmaVIyhfYvRgXfPU/TuERtL9f8pAII44
jAVcy60MBZ1bCwQZcToZlfWCpO/8nLg4nnv4e3W9UeC6rDgWgpI6IXS3jikN/x3P
9JIVFcWLtsOLC+D/33jSV8XDM3qTTRv4i/M+mva6znOI89KcBjsEhX5AunSQZ4Zg
QkQTJi/td+5kVi00NXxlHYH5ztS1
-----END CERTIFICATE-----
EOM

echo 'cert=/etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openvpn]
accept = 443
connect = 127.0.0.1:1194'| sudo tee /etc/stunnel/stunnel.conf





sudo add-apt-repository ppa:linrunner/tlp -y
sudo apt-get update -y
sudo apt-get install tlp tlp-rdw -y
sudo tlp start

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
SELINUX=disabled 
sysctl -p

iptables -F; iptables -X; iptables -Z
iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o eth0 -j SNAT --to-source `curl ipecho.net/plain`
iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o ens3 -j SNAT --to-source `curl ipecho.net/plain`
iptables -t nat -A POSTROUTING -s 10.9.0.0/16 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.9.0.0/16 -o eth0 -j SNAT --to-source `curl ipecho.net/plain`
iptables -t nat -A POSTROUTING -s 10.9.0.0/16 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.9.0.0/16 -o ens3 -j SNAT --to-source `curl ipecho.net/plain`

sudo usermod -a -G www-data root
sudo chgrp -R www-data /var/www
sudo chmod -R g+w /var/www

sudo timedatectl set-timezone Asia/Manila
timedatectl

sudo apt install debconf-utils -y

echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get install iptables-persistent -y

iptables-save > /etc/iptables/rules.v4 
ip6tables-save > /etc/iptables/rules.v6

apt-get install php php-mysqli php-mysql php-gd php-mbstring python -y
apt-get install netcat lsof php php-mysqli php-mysql php-gd php-mbstring python -y

cat << \socksopenvpn > /usr/local/sbin/proxy.py
#!/usr/bin/env python3
# encoding: utf-8
# SocksProxy By: Ykcir Ogotip Caayon
import socket, threading, thread, select, signal, sys, time
from os import system
system("clear")
#conexao
IP = '0.0.0.0'
try:
   PORT = int(sys.argv[1])
except:
   PORT = 8000
PASS = ''
BUFLEN = 8196 * 8
TIMEOUT = 60
MSG = 'SaudiConnect'
DEFAULT_HOST = '0.0.0.0:1194'
RESPONSE = "HTTP/1.1 200 " + str(MSG) + "\r\n\r\n"

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
	self.threadsLock = threading.Lock()
	self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True

        try:                    
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
                
                conn = ConnectionHandler(c, self, addr)
                conn.start();
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()
            
    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()
	
    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()
                    
    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()
                
    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()
            
            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()
			

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Conexao: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True
            
        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
        
            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')
            
            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)
            
            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                if hostPort.startswith(IP):
                    self.method_CONNECT(hostPort)
                else:
                   self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')
    
        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 1194
            else:
                port = 22

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
    	self.log += ' - CONNECT ' + path
        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''
        self.server.printLog(self.log)
        self.doCONNECT()
                    
    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True

            if error:
                break



def main(host=IP, port=PORT):
    print "\033[0;34mâ”"*8,"\033[1;32m PROXY SOCKS","\033[0;34mâ”"*8,"\n"
    print "\033[1;33mIP:\033[1;32m " + IP
    print "\033[1;33mPORTA:\033[1;32m " + str(PORT) + "\n"
    print "\033[0;34mâ”"*10,"\033[1;32m StrongHold","\033[0;34mâ”\033[1;37m"*11,"\n"
    server = Server(IP, PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print '\nClosing...'
            server.close()
            break
if __name__ == '__main__':
    main()
socksopenvpn


cat << \autostart > /root/auto
#!/bin/bash
if nc -z localhost 80; then
    echo "SocksProxy running"
else
    echo "Starting Port 80"
    screen -dmS proxy2 python /usr/local/sbin/proxy.py 80
fi
autostart

chmod +x /root/auto
/root/auto;
crontab -r
echo "SHELL=/bin/bash
* * * * * /bin/bash /root/auto >/dev/null 2>&1" | crontab -


update-rc.d squid3 enable
update-rc.d openvpn enable
update-rc.d apache2 enable
update-rc.d cron enable
update-rc.d stunnel4 enable
update-rc.d tlp enable
service openvpn restart
service squid3 start
service apache2 start
service stunnel4 restart
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/#ForwardToWall=yes/ForwardToWall=no/g' /etc/systemd/journald.conf
clear
echo "Installation Done"
udo apt-get clean > /dev/null 2>&1
history -c
cd /root || exit
rm -f /root/installer.sh
echo -e "\e[1;32m Installing Done \033[0m"
echo 'root:@@Alaminbd257' | sudo chpasswd
reboot
