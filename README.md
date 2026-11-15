# Лабораторна робота 2. TLS та сертифікати

| Поле | Значення |
|---|---|
| ПІБ |Кириленко Олександра Вікторівна |
| Група | ІПЗ 2.01 |
| Ідентифікатор | se-201-10|
| Дата виконання | 13.11.2026|
| Середовище | GitHub Codespaces |
| Версія OpenSSL |OpenSSL 3.5.8 25 Aug 2026 (Library: OpenSSL 3.5.8 25 Aug 2026)|

## Параметри варіанта

| Параметр | Значення |
|---|---|
| Віддалений сервер |`vault.se-201-10.lab` |
| Імена для сертифіката | www.se-201-10.lab`, `blog.se-201-10.lab`|
| Ваш сервер (IP) | `10.53.1.1`|

<!-- Якщо стенд перезапускався під час роботи, вказати, після якого завдання . -->після 2 (повнісстю виконаного), 3 (повнісстю виконаного)

## Завдання 1. HTTP і HTTPS у дампі трафіку

Вивід кроку 1.1:

```
root@se-201-10:/lab/work# cd /lab/work
timeout 8 tcpdump -ni eth0 -A -s0 -l 'host 10.53.0.80 and tcp port 80' > t1-http.txt &
sleep 1; curl -s http://vault.se-201-10.lab/; wait
grep -a -E 'GET /|Host:|server: web' t1-http.txt
[1] 103
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
server: web
Host: vault.se-201-10.lab
SNI: 
protocol: HTTP/1.1 
client: 10.53.1.1
10 packets captured
10 packets received by filter
0 packets dropped by kernel
[1]+  Exit 124                timeout 8 tcpdump -ni eth0 -A -s0 -l 'host 10.53.0.80 and tcp port 80' > t1-http.txt
16:01:00.463474 IP 10.53.1.1.54496 > 10.53.0.80.80: Flags [P.], seq 1:83, ack 1, win 502, options [nop,nop,TS val 3166148983 ecr 3822205704], length 82: HTTP: GET / HTTP/1.1
...w..;.GET / HTTP/1.1
Host: vault.se-201-10.lab
server: web
Host: vault.se-201-10.lab
```

Вивід кроку 1.2:

```
root@se-201-10:/lab/work# timeout 8 tcpdump -ni eth0 -A -s0 -l 'host 10.53.0.80 and tcp port 443' > t1-https.txt &
sleep 1; curl -s --cacert $STAND_CA https://vault.se-201-10.lab/; wait                  
grep -a -c -E 'GET /|server: web' t1-https.txt                                          
grep -a -o 'vault.se-201-10.lab' t1-https.txt | wc -l  
[1] 132
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
server: web
Host: vault.se-201-10.lab
SNI: vault.se-201-10.lab
protocol: HTTP/2.0 TLSv1.3
client: 10.53.1.1
22 packets captured
22 packets received by filter
0 packets dropped by kernel
[1]+  Exit 124                timeout 8 tcpdump -ni eth0 -A -s0 -l 'host 10.53.0.80 and tcp port 443' > t1-https.txt
0
1

```

| Що шукали в дампі | HTTP | HTTPS |
|---|---|---|
| рядок запиту `GET /` | Видно| Не видно|
| заголовок `Host` | Видно| Не видно|
| тіло відповіді (`server: web`) | Видно|Не видно |
| ім'я віддаленого сервера (кількість входжень) |2 | 1|

1. У якому повідомленні і в якому полі передається ім'я сервера, яке видно в дампі HTTPS?
Ім’я сервера передається в повідомленні ClientHello під час TLS-рукостискання. Воно міститься в  SNI  у  нашому випадку це vault.se-201-10.lab.
2. Чому рядок `SNI:` у відповіді сервера порожній для HTTP і заповнений для HTTPS?
Для HTTP TLS-рукостискання не відбувається, тому SNI відсутній. Для HTTPS клієнт передає ім’я сервера через розширення SNI під час TLS-рукостискання
3. Рядок `protocol:` показує HTTP/1.1 для запиту по HTTP і HTTP/2.0 для запиту по HTTPS, хоча обидва запити виконано однією командою `curl` без додаткових ключів. Що визначило версію HTTP у другому випадку?
Версію HTTP у другому випадку визначило розширення ALPN. Під час TLS-рукостискання curl повідомляє серверу, які протоколи підтримує, зокрема HTTP/2 та HTTP/1.1. Сервер обрав HTTP/2, що підтверджується рядком ALPN protocol: h2. У випадку звичайного HTTP TLS-рукостискання не відбувається, тому ALPN не використовується, а curl застосував HTTP/1.1.
## Завдання 2. Рукостискання по записах

Вивід кроку 2.1 (TLS 1.3):

```
openssl s_client -connect vault.se-201-10.lab:443 -servername vault.se-201-10.lab -alpn h2,http/1.1 \
  -CAfile $STAND_CA -trace </dev/null > t2-13.txt 2>&1
grep -a -E '^(Sent|Received) Record|Content Type|^    [A-Z][A-Za-z]+, Length' t2-13.txt
grep -a -E '^(ALPN|New,)|Verify return' t2-13.txt 
Sent Record
  Content Type = Handshake (22)
    ClientHello, Length=330
Received Record
  Content Type = Handshake (22)
    ServerHello, Length=118
Received Record
  Content Type = ChangeCipherSpec (20)
Received Record
  Content Type = ApplicationData (23)
  Inner Content Type = Handshake (22)
    EncryptedExtensions, Length=15
Received Record
  Content Type = ApplicationData (23)
  Inner Content Type = Handshake (22)
    Certificate, Length=987
Received Record
  Content Type = ApplicationData (23)
  Inner Content Type = Handshake (22)
    CertificateVerify, Length=74
Received Record
  Content Type = ApplicationData (23)
  Inner Content Type = Handshake (22)
    Finished, Length=48
Sent Record
  Content Type = ChangeCipherSpec (20)
Sent Record
  Content Type = ApplicationData (23)
  Inner Content Type = Handshake (22)
    Finished, Length=48
Sent Record
  Content Type = ApplicationData (23)
  Inner Content Type = Alert (21)
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
ALPN protocol: h2
Verify return code: 0 (ok)

```

Вивід кроку 2.2 (TLS 1.2):

```
root@se-201-10:/lab/work# openssl s_client -connect vault.se-201-10.lab:443 -servername vault.se-201-10.lab -alpn h2,http/1.1 \
  -CAfile $STAND_CA -tls1_2 -trace </dev/null > t2-12.txt 2>&1
grep -a -E '^(Sent|Received) Record|Content Type|^    [A-Z][A-Za-z]+, Length' t2-12.txt
grep -a -E '^(ALPN|New,)|Verify return' t2-12.txt     
Sent Record
  Content Type = Handshake (22)
    ClientHello, Length=225
Received Record
  Content Type = Handshake (22)
    ServerHello, Length=74
Received Record
  Content Type = Handshake (22)
    Certificate, Length=982
Received Record
  Content Type = Handshake (22)
    ServerKeyExchange, Length=111
Received Record
  Content Type = Handshake (22)
    ServerHelloDone, Length=0
Sent Record
  Content Type = Handshake (22)
    ClientKeyExchange, Length=33
Sent Record
  Content Type = ChangeCipherSpec (20)
Sent Record
  Content Type = Handshake (22)
    Finished, Length=12
Received Record
  Content Type = Handshake (22)
    NewSessionTicket, Length=214
Received Record
  Content Type = ChangeCipherSpec (20)
Received Record
  Content Type = Handshake (22)
    Finished, Length=12
Received Record
  Content Type = ApplicationData (23)
Sent Record
  Content Type = Alert (21)
New, TLSv1.2, Cipher is ECDHE-ECDSA-AES256-GCM-SHA384
ALPN protocol: h2
    Verify return code: 0 (ok)

```

| № | Напрям | `Content Type` | `Inner Content Type` | Повідомлення | `Length` |
|---|---|---|---|---|---|
| 1 | K->C| Handshake (22)| -|ClientHello| 330|
| 2 | C->K|Handshake (22)|- |ServerHello|118|
| 3 | C->K| ChangeCipherSpec (20)| -| -| -|
| 4 | C->K|ApplicationData (23) | Handshake (22)| EncryptedExtensions| 15|
| 5 | C->K| ApplicationData (23)| Handshake (22)|Certificate | 987|
| 6 | C->K| ApplicationData (23)| Handshake (22)| CertificateVerify|74 |
| 7 | C->K| ApplicationData (23| Handshake (22)|Finished | 48|
| 8 | K->C| ChangeCipherSpec (20)| -| - | - |
| 9 | K->C| ApplicationData (23)| Handshake (22)| Finished| 48|
| 10| K->C| ApplicationData (23)| Alert (21)|- | -|
Вивід кроків 2.3 і 2.4:

```
root@se-201-10:/lab/work# grep -a -A3 'extension_type=server_name' t2-13.txt | head -4
        extension_type=server_name(0), length=24
          0000 - 00 16 00 00 13 76 61 75-6c 74 2e 73 65 2d 32   .....vault.se-2
          000f - 30 31 2d 31 30 2e 6c 61-62                     01-10.lab
        extension_type=ec_point_formats(11), length=4
root@se-201-10:/lab/work# for v in 1.3 1.2; do
  timeout 6 tcpdump -ni eth0 -A -s0 -l 'host 10.53.0.80 and tcp port 443' > t2-dump-$v.txt &
  sleep 1; curl -s -o /dev/null --tlsv1.2 --tls-max $v --cacert $STAND_CA https://vault.se-201-10.lab/; wait
  echo "TLS $v: $(grep -a -c 'OPISM Stand Intermediate' t2-dump-$v.txt)"
done
[1] 152
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
22 packets captured
22 packets received by filter
0 packets dropped by kernel
[1]+  Exit 124                timeout 6 tcpdump -ni eth0 -A -s0 -l 'host 10.53.0.80 and tcp port 443' > t2-dump-$v.txt
TLS 1.3: 0
[1] 158
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
21 packets captured
21 packets received by filter
0 packets dropped by kernel
[1]+  Exit 124                timeout 6 tcpdump -ni eth0 -A -s0 -l 'host 10.53.0.80 and tcp port 443' > t2-dump-$v.txt
TLS 1.2: 2

```

| Показник | TLS 1.3 | TLS 1.2 |
|---|---|---|
| Довжина ClientHello, байт | 330| 225|
| Номер першого запису, тип якого спостерігач не бачить | 4| 12|
| Кількість RTT від ClientHello до першого HTTP-запиту | 1|2 |
| Чи видно сертифікат у дампі (результат 2.4) |ні  | так|
| Обраний протокол ALPN | h2 |h2 |

1. За якими рядками виводу 2.1 визначено, з якого запису починається шифрування? Що бачить спостерігач замість типу кожного наступного запису?
У TLS 1.3 шифрування починається з 4-го запису, що видно за рядком Content Type = ApplicationData (23); Спостерігач бачить зовнішній тип ApplicationData (23), але не бачить справжній внутрішній тип повідомлення
2. Чому ClientHello у TLS 1.3 довший, ніж у TLS 1.2? Назвіть розширення, яке за рахунок цього скорочує рукостискання на один RTT.
Можливо, через додаткові розширення
3. Довжина розширення `server_name` у виводі 2.3 становить 17 байт для імені з 12 символів. З яких частин складається це значення і яким воно буде для вашого імені?
Довжина розширення складається з: 2 байти — довжина списку імен; 1 байт— тип імені; 2 байти — довжина самого імені; N байтів— символи доменного імені
Для мого імені vault.se-201-10.lab довжина становить 19 символів
Отже:2+1+2+19=24 байти
5. Навіщо в TLS 1.3 передається запис ChangeCipherSpec, якщо в рукостисканні він нічого не змінює?
У TLS 1.3 пакет ChangeCipherSpec передається просто «для сумісності зі старим обладнанням та захисними екранами у мережі», які звикли бачити його під час рукостискання. У новій версії протоколу він не несе жодної користі для безпеки і нічого не шифрує
## Завдання 3. Сертифікат для власного сервера

Вивід кроків 3.1 і 3.2:

```
root@se-201-10:/lab/work# acme-root
openssl x509 -in /lab/tls/acme-root.crt -noout -subject -dates
збережено /lab/tls/acme-root.crt
subject=CN = Pebble Root CA 6f46a6
notBefore=Nov 13 19:49:45 2026 GMT
notAfter=Nov 13 19:49:45 2056 GMT
root@se-201-10:/lab/work# curl -sS --cacert /lab/tls/acme-root.crt https://www.se-201-10.lab/
curl: (60) SSL certificate problem: self-signed certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.

```

Вивід кроку 3.3 (останні рядки `lego` і рядки журналу nginx):

```
root@se-201-10:/lab/work# lego --server $ACME_DIR --email admin@se-201-10.lab --accept-tos --path /lab/work/lego \
  --http --http.webroot /var/www/acme \
  --domains www.se-201-10.lab --domains blog.se-201-10.lab run --no-bundle
grep acme-challenge /var/log/nginx/access.log
2026/11/13 19:59:34 No key found for account admin@se-201-10.lab. Generating a P256 key.
2026/11/13 19:59:34 Saved key to /lab/work/lego/accounts/ca.lab_14000/admin@se-201-10.lab/keys/admin@se-201-10.lab.key
2026/11/13 19:59:34 [INFO] acme: Registering account for admin@se-201-10.lab
!!!! HEADS UP !!!!

Your account credentials have been saved in your Let's Encrypt
configuration directory at "/lab/work/lego/accounts".

You should make a secure backup of this folder now. This
configuration directory will also contain certificates and
private keys obtained from Let's Encrypt so making regular
backups of this folder is ideal.
2026/11/13 19:59:34 [INFO] [www.se-201-10.lab, blog.se-201-10.lab] acme: Obtaining SAN certificate
2026/11/13 19:59:34 [INFO] [blog.se-201-10.lab] AuthURL: https://ca.lab:14000/authZ/peXDQN4BwpwZVPsTNabvXHFztQkZzr1VsbHsKe7H50M
2026/11/13 19:59:34 [INFO] [www.se-201-10.lab] AuthURL: https://ca.lab:14000/authZ/JGJAfP-Dxxy5Mmt2-oTl4t4qLwPuWOc2H0_wSuVG4fg
2026/11/13 19:59:34 [INFO] [blog.se-201-10.lab] acme: Could not find solver for: tls-alpn-01
2026/11/13 19:59:34 [INFO] [blog.se-201-10.lab] acme: use http-01 solver
2026/11/13 19:59:34 [INFO] [www.se-201-10.lab] acme: Could not find solver for: tls-alpn-01
2026/11/13 19:59:34 [INFO] [www.se-201-10.lab] acme: use http-01 solver
2026/11/13 19:59:34 [INFO] [blog.se-201-10.lab] acme: Trying to solve HTTP-01
2026/11/13 19:59:41 [INFO] [blog.se-201-10.lab] The server validated our request
2026/11/13 19:59:41 [INFO] [www.se-201-10.lab] acme: Trying to solve HTTP-01
2026/11/13 19:59:44 [INFO] [www.se-201-10.lab] The server validated our request
2026/11/13 19:59:44 [INFO] [www.se-201-10.lab, blog.se-201-10.lab] acme: Validations succeeded; requesting certificates
2026/11/13 19:59:44 [INFO] Wait for certificate [timeout: 30s, interval: 500ms]
2026/11/13 19:59:44 [INFO] [www.se-201-10.lab] Server responded with a certificate.
10.53.0.10 - - [13/Nov/2026:19:59:35 +0000] "GET /.well-known/acme-challenge/cLWVESmy5LVvTCyX0buoG-ltI0GVpQBKpQ75BrKVmnQ HTTP/1.1" 200 87 "-" "LetsEncrypt-Pebble-VA (linux; amd64)"
10.53.0.10 - - [13/Nov/2026:19:59:35 +0000] "GET /.well-known/acme-challenge/cLWVESmy5LVvTCyX0buoG-ltI0GVpQBKpQ75BrKVmnQ HTTP/1.1" 200 87 "-" "LetsEncrypt-Pebble-VA (linux; amd64)"
10.53.0.10 - - [13/Nov/2026:19:59:35 +0000] "GET /.well-known/acme-challenge/cLWVESmy5LVvTCyX0buoG-ltI0GVpQBKpQ75BrKVmnQ HTTP/1.1" 200 87 "-" "LetsEncrypt-Pebble-VA (linux; amd64)"
10.53.0.10 - - [13/Nov/2026:19:59:41 +0000] "GET /.well-known/acme-challenge/SWH6DdGrYt3zs0y7_scGFdq-rL6IekPIkw6j0VmjZeE HTTP/1.1" 200 87 "-" "LetsEncrypt-Pebble-VA (linux; amd64)"
10.53.0.10 - - [13/Nov/2026:19:59:41 +0000] "GET /.well-known/acme-challenge/SWH6DdGrYt3zs0y7_scGFdq-rL6IekPIkw6j0VmjZeE HTTP/1.1" 200 87 "-" "LetsEncrypt-Pebble-VA (linux; amd64)"
10.53.0.10 - - [13/Nov/2026:19:59:41 +0000] "GET /.well-known/acme-challenge/SWH6DdGrYt3zs0y7_scGFdq-rL6IekPIkw6j0VmjZeE HTTP/1.1" 200 87 "-" "LetsEncrypt-Pebble-VA (linux; amd64)"

```

Вивід кроку 3.4:

```
root@se-201-10:/lab/work# cd /lab/work/lego/certificates
openssl x509 -in www.se-201-10.lab.crt -noout -subject -issuer -dates -serial -ext subjectAltName
openssl x509 -in www.se-201-10.lab.issuer.crt -noout -subject -issuer
subject=CN = www.se-201-10.lab
issuer=CN = Pebble Intermediate CA 43abf7
notBefore=Nov 13 19:59:44 2026 GMT
notAfter=Nov 13 19:59:43 2031 GMT
serial=1605776D048B885A
X509v3 Subject Alternative Name: 
    DNS:www.se-201-10.lab, DNS:blog.se-201-10.lab
subject=CN = Pebble Intermediate CA 43abf7
issuer=CN = Pebble Root CA 6f46a6

```

Вивід кроку 3.5:

```
root@se-201-10:/lab/work/lego/certificates# cp www.se-201-10.lab.crt /lab/tls/server.crt
cp www.se-201-10.lab.key /lab/tls/server.key
web-reload
curl -sS --cacert /lab/tls/acme-root.crt https://www.se-201-10.lab/
openssl s_client -connect www.se-201-10.lab:443 -servername www.se-201-10.lab -CAfile /lab/tls/acme-root.crt \
  </dev/null 2>/dev/null | sed -n '/^Certificate chain/,/^---/p;/^Verify return code/p'
nginx: the configuration file /lab/nginx.conf syntax is ok
nginx: configuration file /lab/nginx.conf test is successful
2026/11/13 20:01:56 [notice] 47#47: signal process started
curl: (60) SSL certificate problem: self-signed certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
Certificate chain
 0 s:CN = www.se-201-10.lab
   i:CN = Pebble Intermediate CA 43abf7
   a:PKEY: id-ecPublicKey, 256 (bit); sigalg: RSA-SHA256
   v:NotBefore: Nov 13 19:59:44 2026 GMT; NotAfter: Nov 13 19:59:43 2031 GMT
---
Verify return code: 21 (unable to verify the first certificate)

```

Вивід кроку 3.6:

```
root@se-201-10:/lab/work/lego/certificates# cat www.se-201-10.lab.crt www.se-201-10.lab.issuer.crt > /lab/tls/server.crt
web-reload
curl -sS --cacert /lab/tls/acme-root.crt https://www.se-201-10.lab/
openssl s_client -connect www.se-201-10.lab:443 -servername www.se-201-10.lab -CAfile /lab/tls/acme-root.crt \
  </dev/null 2>/dev/null | sed -n '/^Certificate chain/,/^---/p;/^Verify return code/p'
curl -sS --cacert /lab/tls/acme-root.crt https://blog.se-201-10.lab/
nginx: the configuration file /lab/nginx.conf syntax is ok
nginx: configuration file /lab/nginx.conf test is successful
2026/11/13 20:02:02 [notice] 55#55: signal process started
server: se-201-10 (https)
Host: www.se-201-10.lab
SNI: www.se-201-10.lab
protocol: TLSv1.3
Certificate chain
 0 s:CN = www.se-201-10.lab
   i:CN = Pebble Intermediate CA 43abf7
   a:PKEY: id-ecPublicKey, 256 (bit); sigalg: RSA-SHA256
   v:NotBefore: Nov 13 19:59:44 2026 GMT; NotAfter: Nov 13 19:59:43 2031 GMT
 1 s:CN = Pebble Intermediate CA 43abf7
   i:CN = Pebble Root CA 6f46a6
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Nov 13 19:49:45 2026 GMT; NotAfter: Nov 13 19:49:45 2056 GMT
---
Verify return code: 0 (ok)
server: se-201-10 (https)
Host: blog.se-201-10.lab
SNI: blog.se-201-10.lab
protocol: TLSv1.3

```

| Параметр | Значення |
|---|---|
| Видавець сертифіката сервера |CN = Pebble Intermediate CA 43abf7 |
| Видавець сертифіката видавця | CN = Pebble Root CA 6f46a6|
| Імена в SAN |www.se-201-10.lab,blog.se-201-10.lab |
| Строк дії (від – до) | notBefore=Nov 13 19:59:44 2026 GMT
notAfter=Nov 13 19:59:43 2031 GMT|
| Тип ключа сервера і алгоритм підпису | id-ecPublicKey, 256 (bit); sigalg: RSA-SHA256|
| Кількість сертифікатів, які надсилає сервер, у кроці 3.5 і в кроці 3.6 | У кроці 3.5 - 1 сертифікат (тільки серверний); у кроці 3.6 — 2 сертифікати (серверний + проміжний)|

1. Хто і як перевірив, що ви контролюєте обидва імена? Вкажіть рядки виводу, які це підтверджують.
Тестовий центр Pebble перевірив, чи справді домен належить нам. Для цього клієнт lego створив спеціальні файли та розмістив їх на сервері. Після цього центр сертифікації зайшов на сервер через HTTP і перевірив ці файли, щоб підтвердити право власності на домен; Рядки:
2026/11/13 19:59:34 [INFO] [www.se-201-10.lab, blog.se-201-10.lab] acme: Obtaining SAN certificate
2026/11/13 19:59:34 [INFO] [blog.se-201-10.lab] AuthURL: https://ca.lab:14000/authZ/peXDQN4BwpwZVPsTNabvXHFztQkZzr1VsbHsKe7H50M
2026/11/13 19:59:34 [INFO] [www.se-201-10.lab] AuthURL: https://ca.lab:14000/authZ/JGJAfP-Dxxy5Mmt2-oTl4t4qLwPuWOc2H0_wSuVG4fg
2026/11/13 19:59:34 [INFO] [blog.se-201-10.lab] acme: Could not find solver for: tls-alpn-01
2026/11/13 19:59:34 [INFO] [blog.se-201-10.lab] acme: use http-01 solver
2026/11/13 19:59:34 [INFO] [www.se-201-10.lab] acme: Could not find solver for: tls-alpn-01
2026/11/13 19:59:34 [INFO] [www.se-201-10.lab] acme: use http-01 solver
2026/11/13 19:59:34 [INFO] [blog.se-201-10.lab] acme: Trying to solve HTTP-01
2026/11/13 19:59:41 [INFO] [blog.se-201-10.lab] The server validated our request
2026/11/13 19:59:41 [INFO] [www.se-201-10.lab] acme: Trying to solve HTTP-01
2026/11/13 19:59:44 [INFO] [www.se-201-10.lab] The server validated our request
2026/11/13 19:59:44 [INFO] [www.se-201-10.lab, blog.se-201-10.lab] acme: Validations succeeded; requesting certificates
2026/11/13 19:59:44 [INFO] Wait for certificate [timeout: 30s, interval: 500ms]
2026/11/13 19:59:44 [INFO] [www.se-201-10.lab] Server responded with a certificate.
2. Чому в кроці 3.5 перевірка не пройшла, хоча корінь центру сертифікації вказано в `--cacert`, а сертифікат виданий правильно?
Перевірка не пройшла, тому що сервер надіслав тільки свій сертифікат, але не надіслав проміжний сертифікат (Intermediate CA). Клієнт довіряв кореневому сертифікату (Root CA), але через відсутність проміжного сертифіката не зміг перевірити весь ланцюжок і підтвердити, що сертифікат сервера є надійним.
3. У виводі ланцюжка для сертифіката сервера вказано `id-ecPublicKey` і `RSA-SHA256`. Що означає кожне з цих значень і чому вони не суперечать одне одному?
Вони не суперечать один одному тому що виконують різні функції: id-ecPublicKey вказує на тип публічного ключа, який використовується в сертифікаті для встановлення захищеного з’єднання,а RSA-SHA256 — це алгоритм цифрового підпису, за допомогою якого проміжний центр сертифікації підписав цей сертифікат. 
4. Що станеться з перевіркою вашого сервера після перезапуску стенда і чому? Що в реальній інфраструктурі відповідає цій ситуації?
Перевірка перестане працювати, тому що після перезапуску контейнера Pebble створюється заново та генерує нові криптографічні ключі для Root CA та Intermediate CA. Через це старий сертифікат більше не буде довіреним для нового центру сертифікації.
У реальному житті таке може статися, наприклад, коли компанія змінює центр сертифікації або оновлює свою систему сертифікатів. Через це старі сертифікати можуть перестати вважатися надійними. Також проблема може виникнути, якщо сертифікат закінчився, а його вчасно не оновили.
## Завдання 4. Діагностика несправностей

Вивід кроку 4.1:

```
root@se-201-10:/lab/work# for i in 1 2 3 4 5; do
  n=f$i.se-201-10.lab; echo "=== $n"
  curl -sS --cacert $STAND_CA https://$n/ 2>&1 | head -1
  openssl s_client -connect $n:443 -servername $n -CAfile $STAND_CA </dev/null 2>/dev/null \
    | sed -n '/^Certificate chain/,/^---/p;/^Verify return code/p' | grep -v PKEY
done
=== f1.se-201-10.lab
server: web, f1
Certificate chain
 0 s:CN = f1.se-201-10.lab
   i:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   v:NotBefore: Nov 13 15:11:08 2026 GMT; NotAfter: Feb 11 15:11:08 2027 GMT
 1 s:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   i:O = OPISM Lab, CN = OPISM Stand Root CA
   v:NotBefore: Nov 13 15:11:08 2026 GMT; NotAfter: Nov 12 15:11:08 2031 GMT
---
Verify return code: 0 (ok)
=== f2.se-201-10.lab
curl: (60) SSL certificate problem: self-signed certificate
Certificate chain
 0 s:CN = f2.se-201-10.lab
   i:CN = f2.se-201-10.lab
   v:NotBefore: Nov 13 15:11:08 2026 GMT; NotAfter: Feb 11 15:11:08 2027 GMT
---
Verify return code: 18 (self-signed certificate)
=== f3.se-201-10.lab
curl: (60) SSL: no alternative certificate subject name matches target host name 'f3.se-201-10.lab'
Certificate chain
 0 s:CN = staging.se-201-10.lab
   i:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   v:NotBefore: Nov 13 15:11:08 2026 GMT; NotAfter: Feb 11 15:11:08 2027 GMT
 1 s:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   i:O = OPISM Lab, CN = OPISM Stand Root CA
   v:NotBefore: Nov 13 15:11:08 2026 GMT; NotAfter: Nov 12 15:11:08 2031 GMT
---
Verify return code: 0 (ok)
=== f4.se-201-10.lab
curl: (60) SSL certificate problem: certificate has expired
Certificate chain
 0 s:CN = f4.se-201-10.lab
   i:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   v:NotBefore: Apr 27 15:11:08 2026 GMT; NotAfter: Oct 24 15:11:08 2026 GMT
 1 s:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   i:O = OPISM Lab, CN = OPISM Stand Root CA
   v:NotBefore: Nov 13 15:11:08 2026 GMT; NotAfter: Nov 12 15:11:08 2031 GMT
---
Verify return code: 10 (certificate has expired)
=== f5.se-201-10.lab
curl: (60) SSL certificate problem: unable to get local issuer certificate
Certificate chain
 0 s:CN = f5.se-201-10.lab
   i:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   v:NotBefore: Nov 13 15:11:08 2026 GMT; NotAfter: Feb 11 15:11:08 2027 GMT
---
Verify return code: 21 (unable to verify the first certificate)

```

| Сервер | Помилка `curl` | `Verify return code` | Яка перевірка не пройшла | Рядок виводу, що це доводить | Що має змінити власник сервера |
|---|---|---|---|---|---|
| f1 |- | 0 (ok)| -| Verify return code: 0 (ok)| -|
| f2 | SSL certificate problem: self-signed certificate| 18 (self-signed certificate)| Перевірка на самопідписаний сертифікат| 0 s:CN = f2.se-201-10.lab
   i:CN = f2.se-201-10.lab| Замовити та встановити сертифікат, підписаний справжнім довіреним центром сертифікації (CA), а не підписувати його самостійно власним ключем|
| f3 |SSL: no alternative certificate subject name matches target host name 'f3.se-201-10.lab' | 0 (ok)|Перевірка відповідності імені хоста | 0 s:CN = staging.se-201-10.lab
   i:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   v:NotBefore: Nov 13 15:11:08 2026 GMT; NotAfter: Feb 11 15:11:08 2027 GMT
 1 s:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   i:O = OPISM Lab, CN = OPISM Stand Root CA|Перевипустити сертифікат, обов'язково додавши правильне ім'я (f3.se-201-10.lab) |
| f4 |SSL certificate problem: certificate has expired | 10 (certificate has expired)| Перевірка терміну дії сертифіката| v:NotBefore: Apr 27 15:11:08 2026 GMT; NotAfter: Oct 24 15:11:08 2026 GMT| Оновити сертифікат|
| f5 |SSL certificate problem: unable to get local issuer certificate | 21 (unable to verify the first certificate)| Перевірка ланцюжка довіри (відсутній проміжний сертифікат видавця)|Certificate chain
 0 s:CN = f5.se-201-10.lab
   i:O = OPISM Lab, CN = OPISM Stand Intermediate CA
   v:NotBefore: Nov 13 15:11:08 2026 GMT; NotAfter: Feb 11 15:11:08 2027 GMT (відсутній блок сертифіката) | Потрібно налаштувати вебсервер так, щоб він надсилав не тільки свій сертифікат, а й проміжний сертифікат центру сертифікації, тоді клієнт зможе перевірити весь ланцюжок сертифікатів і переконатися, що з'єднання є безпечним|

1. Для сервера з помилкою `unable to get local issuer certificate` визначте, яка це несправність: сервер не надсилає проміжний сертифікат чи сертифікат виданий центром, якому клієнт не довіряє. Чим ці дві несправності відрізняються у виводі `openssl s_client`?
У сервера f5 помилка unable to get local issuer certificate виникла через те, що сервер не надсилає проміжний сертифікат 
У розділі Certificate chain є тільки сертифікат самого сервера (f5.se-201-10.lab), але немає проміжного сертифіката.
Якби сертифікат був виданий центром, якому клієнт не довіряє, то вивід міг би містити повний ланцюжок сертифікатів, але перевірка все одно завершилася б помилкою, оскільки клієнт не має відповідного кореневого сертифіката у списку довірених
Отже, різниця в тому, що в першому випадку не вистачає сертифіката в ланцюжку, а в другому — клієнт не довіряє центру, який видав сертифікат
2. Якщо серед ваших серверів є сервер з невідповідним ім'ям, чому `openssl s_client` повертає для нього `Verify return code: 0 (ok)`, а `curl` повідомляє про помилку? Якщо такого сервера немає, дайте відповідь для загального випадку.
У моєму випадку це сервер f3
Причина в тому, що openssl s_client перевіряє правильність ланцюжка сертифікатів і довіру до центру сертифікації, але без додаткових параметрів не перевіряє відповідність імені сервера імені в сертифікаті.
А curl перевіряє не тільки довіру до сертифіката, а й те, чи збігається ім'я хоста з іменем, зазначеним у сертифікаті.
У нашому випадку ми звертаємося до f3.se-201-10.lab, а в сертифікаті вказано staging.se-201-10.lab. Тому curl повідомляє про помилку, хоча openssl s_client показує
Verify return code: 0 (ok)
3. Які з п'яти серверів відповіли б на запит `curl -k`? Що при цьому втрачається порівняно з `--cacert`?
На запит curl -k повинні відповісти всі п'ять серверів: f1, f2, f3, f4 і f5, якщо вони доступні та правильно налаштовані для HTTPS
Параметр -k вимикає перевірку SSL-сертифіката, тобто curl ігнорує проблеми з довірою до сертифіката, невідповідністю імені, закінченням терміну дії та неповним ланцюжком сертифікатів.
Порівняно з параметром --cacert втрачається перевірка справжності сервера. Клієнт уже не може переконатися, що підключився саме до потрібного сервера, а не до стороннього, який може видавати себе за нього
--cacert дозволяє вказати довірений сертифікат CA, за допомогою якого перевіряється сертифікат сервера, а -k просто ігнорує помилки перевірки.
## Завдання 5. Ціна нового з'єднання

**Прогноз** (записати до вимірювання). Скільки RTT мине до завершення кожного етапу:

| Етап | TLS 1.3, нове з'єднання | TLS 1.2, нове з'єднання | Повторне використання з'єднання |
|---|---|---|---|
| `time_connect` |1 | 1|0|
| `time_appconnect` |1 | 2| 0|
| `time_starttransfer` | 1| 1| 1|

Вивід кроків 5.2 і 5.3:

```
root@se-201-10:/lab/work# F='%{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{http_version} %{num_connects}\n'
U=https://vault.se-201-10.lab/
for i in 1 2 3; do curl -s -o /dev/null --cacert /lab/pki/stand-root.crt -w "$F" $U; done
for i in 1 2 3; do curl -s -o /dev/null --tls-max 1.2 --cacert /lab/pki/stand-root.crt -w "$F" $U; done
0.051542 0.076693 0.105147 0.130423 0.130465 2 1
0.025687 0.050836 0.078837 0.104997 0.105080 2 1
0.025370 0.050692 0.078913 0.104239 0.104291 2 1
0.025368 0.050455 0.103563 0.128878 0.128931 2 1
0.025768 0.050958 0.104798 0.130120 0.130183 2 1
0.025398 0.050596 0.104964 0.130296 0.130358 2 1
root@se-201-10:/lab/work# curl -s --cacert /lab/pki/stand-root.crt -w "$F" -o /dev/null $U -o /dev/null $U -o /dev/null $U
0.025387 0.050510 0.078540 0.103850 0.103900 2 1
0.000017 0.000000 0.000000 0.025216 0.025254 2 0
0.000015 0.000000 0.000000 0.025303 0.025344 2 0

```


| Запит | `namelookup` | `connect` | `appconnect` | `starttransfer` | `total` | `num_connects` |
|---|---|---|---|---|---|---|
| TLS 1.3, нове |25.687| 50.836| 78.913| 104.997| 105.080| 1|
| TLS 1.2, нове |25.398 | 50.596| 104.798|130.120 | 130.296| 1|
| 5.3, перший запит | 25.387|50.510 | 78.540|103.850 |103.900 | 1|
| 5.3, другий запит | 0.017| 0| 0|25.216 | 25.254| 0|
| 5.3, третій запит | 0.015| 0| 0| 25.303| 25.344| 0|

RTT, визначений вимірюванням, і з якого значення його визначено:
Оскільки namelookup показує час DNS-пошуку, а connect — загальний час до встановлення TCP-з'єднання, я вирішила відняти час DNS-пошуку від часу встановлення з'єднання. Таким чином отримала приблизний RTT без урахування DNS-пошуку; RTT = connect - namelookup=50.836-25.687=25,149 мс 
1. Виразіть кожне виміряне значення через RTT. Де вимірювання відрізняється від цілого числа RTT і чим це пояснюється?
Для початку я визначила RTT за різницею між часом встановлення TCP-з’єднання (time_connect) та часом DNS-пошуку (time_namelookup):
RTT = 50,836 − 25,687 = 25,149 мс.
Щоб визначити, скільком RTT відповідає кожне вимірювання, я поділила час виконання кожного запиту на отримане значення RTT.
TLS 1.3, нове з’єднання: 105,080 / 25,149 =4,18 RTT
TLS 1.2, нове з’єднання: 130,296 / 25,149 = 5,18 RTT
Перший запит (5.3): 103,900 / 25,149= 4,13 RTT
Другий запит (5.3): 25,254 / 25,149 = 1,00 RTT
Третій запит (5.3): 25,344 / 25,149 = 1,01 RTT
Отримані значення не є цілими числами RTT, оскільки на загальний час впливають не тільки мережеві затримки, а й час обробки запитів сервером, виконання TCP- та TLS-операцій і невеликі затримки під час роботи системи.
2. Чому `time_namelookup` не близький до нуля, хоча резолвер уже має ім'я в кеші? За яких умов він був би приблизно вдвічі більшим?
Навіть якщо DNS-запис уже є в кеші, пошук не займає абсолютно нульовий час. Системі все одно потрібно звернутися до локального резолвера, перевірити кеш і повернути знайдену IP-адресу програмі.
Час time_namelookup міг би бути приблизно вдвічі більшим, якби DNS-запису не було в кеші й довелося виконувати додатковий запит до DNS-сервера. У такому випадку виникла б додаткова мережева затримка
3. Сервіс виконує 200 послідовних запитів до цього сервера. Розрахуйте, скільки часу займе лише очікування мережі, якщо кожен запит встановлює нове з'єднання TLS 1.3, нове з'єднання TLS 1.2 і якщо всі запити йдуть через одне з'єднання.
Для розрахунку я використала отримані під час вимірювань значення часу виконання запитів
1) Кожен запит створює нове TLS 1.3 з’єднання:
T = 200 * 105,080 = 21016 мс= 21,016 с
2) Кожен запит створює нове TLS 1.2 з’єднання:
T = 200 * 130,296 = 26059,2 мс =26,0592 с
3) Усі запити виконуються через одне з’єднання:
Перший запит встановлює з’єднання, а наступні 199 використовують уже відкрите з’єднання
Середній час повторного запиту:
(25,254 + 25,344) / 2 = 25,299 мс
Загальний час:
T= 103,900 + 199 * 25,299 = 5139,601 мс = 5,14 с.
## Висновки

**Що виявилося несподіваним.** Результат, який не збігся з очікуванням, і рядок виводу, де це видно:
Мене здивувало, що навіть правильно виданий сертифікат не гарантує успішного HTTPS-з’єднання. У кроці 3.5 сертифікат був чинним, містив правильне ім’я сервера, але перевірка все одно завершилася помилкою (Verify return code: 21)
Після додавання проміжного сертифіката на кроці 3.6 перевірка завершилася успішно:Verify return code: 0 (ok)

**Яке питання залишилося без відповіді.** Що саме не вдалося пояснити; до якого рядка виводу це стосується; що вже перевірено і що з'ясувати не вдалося:
Чи може браузер успішно перевірити сертифікат, якщо сервер не надіслав проміжний сертифікат, але браузер уже має його у власному кеші?
Якщо потрібно відправити, наприклад, 200 запитів, то HTTP/2 впорається з цим швидше за HTTP/1.1? Чи HTTP/1.1 теж може це робити через одне з'єднання просто не так швидко?
## Декларація використання ШІ

Використовувалися інструменти ШІ: так


| № | Інструмент | Промпт (дослівно) | Що використано у звіті і що змінено самостійно |
|---|---|---|---|
| 1 | GPT |Чому тут помилка? `root@se-201-10:/lab/work# timeout 8 tcpdump -ni eth0 -A -s0 -l 'host 10.53.0.80 and tcp port 443' > t1-https.txt &
sleep 1; curl -s --cacert $STAND_CA https://vault.se-201-10.lab/; wait                  
grep -a -c -E 'GET /|server: web' t1-https.txt                                          
grep -a -o 'vault.se-201-10.lab' t1-https.txt | wc -l                 
[1] 124
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
curl: (2) no URL specified
curl: try 'curl --help' or 'curl --manual' for more information
0 packets captured
0 packets received by filter
0 packets dropped by kernel
[1]+  Exit 124                timeout 8 tcpdump -ni eth0 -A -s0 -l 'host 10.53.0.80 and tcp port 443' > t1-https.txt
0
0 `|Зрозуміла що STAND_CA раніше була порожньою.
За допомогою GPT равильно встановила шлях до кореневого сертифіката.
Файл /lab/pki/stand-root.crt існує і доступний |
| 2 |GPT |Що таке розширення ALPN у TLS і як воно впливає на вибір версії HTTP?|Отримала пояснення, яке допомогло зрозуміти, чому для HTTPS було обрано HTTP/2|
| 3 |GPT |Поясни, чим відрізняються серверний, проміжний і кореневий сертифікати та навіщо сервер повинен передавати проміжний сертифікат|Підтвердила своє розуміння побудови ланцюжка довіри сертифікатів; використала для аналізу помилки Verify return code: 21 у кроці 3.5 та успішної перевірки після додавання проміжного сертифіката у кроці 3.6|
| 4 |GPT |Що означає параметр -k у команді curl -k ? | Завдяки отриманому поясненню мені вдалося самостійно сформулювати відповідь на запитання № 3 у завданні № 4|
