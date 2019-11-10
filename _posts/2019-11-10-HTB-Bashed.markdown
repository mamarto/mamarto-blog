---
layout: post
title:  "HTB Writeup - Bashed"
date:   2019-11-10 12:59:50 +0000
---

# HTB writeup - Bashed
<br />

Hello, today we are going to see how I rooted Bashed from Hack The Box.

This is a very easy machine, let's start with nmap:
```
root@kali:~# nmap -sC -sV 10.10.10.68
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-10 12:40 CET
Nmap scan report for 10.10.10.68
Host is up (0.045s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.30 seconds
```
<br />

As we can see, we only have http.
<br />
http://10.10.10.68:
<img src="/assets/bashed1.PNG" alt="drawing" width="600"/>




<br />
```
gobuster dir -u "http://10.10.10.68" -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.68
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/11/10 11:15:49 Starting gobuster
===============================================================
/images (Status: 301)
/uploads (Status: 301)
/php (Status: 301)
/css (Status: 301)
/dev (Status: 301)
/js (Status: 301)
/fonts (Status: 301)
===============================================================
2019/11/10 11:17:11 Finished
===============================================================
```
<br />

We have interesting files under /dev. Basically there is a web shell written in php. 

We execute it, and we are www-data.

<img src="/assets/bashed2.PNG" alt="drawing" width="600"/>
<br />
I tried to pop a reverse shell in various languages, but it didn't work, probably because it was appending a redirect on each command.
<br />

If we take a look back at the gobuster output, we see that an /uploads folder is available. 
I ran some test, and I found out that if you place a file under "/var/www/html/uploads/file_name" you can execute it from the web server "/uploads/file_name".
I therefore uploaded a php reverse shell and I popped a shell as www-data. 
<br />

I then spawned a python shell with:
```
python -c 'import pty; pty.spawn("/bin/sh")'
```
<br />
Doing some basic enumeration, I found out that www-data can run any command without providing the password as scriptmanager:
```
(scriptmanger : scriptmanager) NOPASSWD: ALL
```
So, once I had a shell I changed user.
```
scriptmanager@bashed:/$ ls -la
ls -la
total 88
drwxr-xr-x  23 root          root           4096 Dec  4  2017 .
drwxr-xr-x  23 root          root           4096 Dec  4  2017 ..
drwxr-xr-x   2 root          root           4096 Dec  4  2017 bin
drwxr-xr-x   3 root          root           4096 Dec  4  2017 boot
drwxr-xr-x  19 root          root           4240 Nov  9 11:29 dev
drwxr-xr-x  89 root          root           4096 Dec  4  2017 etc
drwxr-xr-x   4 root          root           4096 Dec  4  2017 home
lrwxrwxrwx   1 root          root             32 Dec  4  2017 initrd.img -> boot/initrd.img-4.4.0-62-generic
drwxr-xr-x  19 root          root           4096 Dec  4  2017 lib
drwxr-xr-x   2 root          root           4096 Dec  4  2017 lib64
drwx------   2 root          root          16384 Dec  4  2017 lost+found
drwxr-xr-x   4 root          root           4096 Dec  4  2017 media
drwxr-xr-x   2 root          root           4096 Feb 15  2017 mnt
drwxr-xr-x   2 root          root           4096 Dec  4  2017 opt
dr-xr-xr-x 116 root          root              0 Nov  9 11:28 proc
drwx------   3 root          root           4096 Dec  4  2017 root
drwxr-xr-x  18 root          root            500 Nov  9 11:29 run
drwxr-xr-x   2 root          root           4096 Dec  4  2017 sbin
drwxrwxr--   2 scriptmanager scriptmanager  4096 Dec  4  2017 scripts
drwxr-xr-x   2 root          root           4096 Feb 15  2017 srv
dr-xr-xr-x  13 root          root              0 Nov  9 11:28 sys
drwxrwxrwt  10 root          root           4096 Nov 10 03:04 tmp
drwxr-xr-x  10 root          root           4096 Dec  4  2017 usr
drwxr-xr-x  12 root          root           4096 Dec  4  2017 var
lrwxrwxrwx   1 root          root             29 Dec  4  2017 vmlinuz -> boot/vmlinuz-4.4.0-62-generic
<br />
```
the folder scripts really stands out:
```
scriptmanager@bashed:/scripts$ ls -la
ls -la
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Dec  4  2017 .
drwxr-xr-x 23 root          root          4096 Dec  4  2017 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Nov 10 03:05 test.txt

scriptmanager@bashed:/scripts$ date
Sun Nov 10 03:05:07 PST 2019


scriptmanager@bashed:/scripts$ cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close

scriptmanager@bashed:/scripts$ cat test.txt
testing 123!scriptmanager@bashed:/scripts$ 
```
<br />

Inside this folder we have two files, the idea behind this is that the file test.py is run by root each minute and produce the output test.txt. All I need to do was replace the content of test.py with a python reverse shell, and that's it!  


