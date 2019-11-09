---
layout: post
title: "OSINT - Easy Phish Challenge"
date: 2019-11-04 10:00:00 +0000
---


# OSINT - Easy Phish Challenge

Today we are going to see how I solved the Easy Phish Challenge from Hack The Box. <br /> 
Not long ago a new series of challenges about OSINT were published, and since I deal with these topics on a daily basis, I accepted the challenge!
 <br />
Since this challenge is still active, I cannot spoil the details or the steps to get the flag, however I can talk about the theory behind it. <br />
The idea behind this challenge is that you have to figure out why the customers of secure-startup.com have been receiving some very convincing phishing emails.

In order to avoid malicious emails from spoofed addresses, three protocols have to be set up: Sender Policy Framework (SPF), Domain Keys Identified Mail (DKIM) and Domain-Based Message Authentication, Reporting and Conformance (DMARC). These three protocols have been around for years and represent global security standards to secure emails.

To correctly enable these protocols, the domain admin have to configure them in the DNS using TXT records. When successful, receivers can check additional information to verify whether a particular email came from the email domain from which it claims to be sent. 
 <br />
SPF works by extracting the "Return-Path" from email's headers. The receiving server extracts the domain's SPF record, and then checks if the source email server IP is approved to send emails for that domain. 

Receiving servers verify SPF by checking a specific TXT DNS entry in your domain, which includes a list of approved IP addresses. This is one of the key aspects of SPF. By using DNS, it’s able to build on something that every website or application already has. That DNS entry includes several parts which each provide different information to the server.
 <br />
DKIM works by adding a signature header to the email messages, containing values that allow a receiving mail server to validate the email message by looking up a sender’s DKIM key and using it to verify the encrypted signature. The usual "public-key cryptography" approach.  
 <br />
DMARC unifies the SPF and DKIM authentication mechanisms into a common framework and allows domain owners to declare how they would like email from that domain to be handled if it fails an authorization test.
 <br />
Once the basic of these three standards are grasped, it is very straightforward to complete this challenge!
