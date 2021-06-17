# ACIM Botnet: BotNet for Linux

## Executive Summary

ACIM is a golang based DDOS botnet that was first seen on May 3rd 2021 and had zero detections on virus total. Similar variants of this malware were seen in the past and it shares a small gene pool with them and GoldMax malware.

A network of computers that is infected by malware and being controlled by a single attacking party often regarded as “bot-herder” is called a botnet and each infected system is called a bot. Botnets are used to carry various large scale attacks such as email spam, targeted intrusion, DDOS attacks etc. In this case it's a DDOS botnet used to take down web services via http floods.

The malware offers the ability to connect to a command and control server on port 420 and then perform http post and get method based dos attacks when instructed from c2. It has no mechanisms to perform persistence or run any kind of commands on the system. The purpose of the malware is to create an army of infected systems and perform ddos attacks on http based web services.

The malware does no damage to the system it's infecting but it will hog bandwidth that can cause delay or downtime for other services. Also since the malware will make the infected systems participate in DDOS attacks thus it can cause  ip/ip-range to be blacklisted.


## Description

ACIM botnet malware is written in golang and has an active command and control server during the time analysis. The malware is dynamically compiled and has debug symbols and function names still attached to it. It is 80% similar to the previous variants that were found and shares about 7% of its code with GoldMax malware.

The malware does not run commands or executables on the system or has functionality to create backdoors. The motive of the malware is to connect all infected systems to a command and control server and wait for further instructions in order to carry out DDOS attacks on any http based web service.

During the analysis the ip to which malware was connecting was found to be up and running although the botnet connection port i.e 420 was closed. The command and control ip belong to a domain called yumeko.sh and was located in Germany (51.2993 Lat 9.491 Long).

![Malware Genes Identified](images/acim_malware_genre.png)


# Detailed Static Analysis

## Malware MetaData

### File identification
+ MD5: 6426726f24e72f95168f6dd6687c8865
+ Sha1: 32e31e15fe42e4cb9e2a03698a5c7bc386311eb6
+ Sha256: 496a46a07ae436b82b87bef642afbb3b06d9dbf0e0fae0199f6389f312fa4e57
+ Sha512: 817c750530fd0a781181497cad28722d9426c3b0128b83c6a513238b0c28eaded4d9a3d7b8938b3690d4d20aec4d03492f074998702d4c4c36fb936a72a48372
+ SSDeep: 98304:hTf27Uapq5dzGq3nX0ZUhxxbyLtZ/ip1g1hUWzH7yxCcOL2:1f27UapqjzGq3nX0Ziz+Lcg12CuxCZa

+ File Size: 7034136 Bytes

+ Meta Data: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Go BuildID=Owyrv52O2sayBgB4XkPC/gPM7sJzobYcoyF1H1wUQ/6cdenI68NyFI0OM5SKqe/7kg_y0aCylV_oDDl5WOp, not stripped

#### Virus Total
https://www.virustotal.com/gui/file/496a46a07ae436b82b87bef642afbb3b06d9dbf0e0fae0199f6389f312fa4e57/detection

#### Malware Bazaar

https://malshare.com/sample.php?action=detail&hash=5e1cbb6566f677da1d920c9d22f59bd7

## Malicious File Summary

The malware written in golang is intended to create a botnet of infected systems that can later on carry out http based Denials Of Service attacks. The malware is dynamically linked and has not been stripped of debug symbols during compilation thus providing actual names of functions and libraries that were used.

When run, malware will first try to connect to its command and control at port 420 and confirm initial connection and then will wait for further instruction. The malware has only two DDOS functions i.e SimpleGet and SimplePost.

First the main.main function is run whose job is to connect to the command and control framework and if that fails try again. Once a successful connection is established main.AwaitCommands is run.


![main.main Function](images/acim_main_func.png)

Function call tree of the main function is as follows.

![Function Call Tree for main.main](images/acim_main_func_call_tree.png)

The main.main function has calls to 2 important functions i.e main.Connect and main.AwaitCommands.

![main.Connect function is called from main.main](images/acim_botnet_main_main.png)


![Command and Control IP string defined](images/acim_ip_address.png)


![ip address is pop from stack and net.Dial function is called](images/acim_tcp_connection.png)

At the time of analysis the command and control was not listening on port 420 thus no new zombie computer could connect thus the following error message was being printed.

![Malware During Execution](images/acim_running.png)

On successful connection to the command and control framework the malware prints a success message and then begins to run the main.AwaitCommands. The main.AwaitCommands is a controller for the malware and will take instructions from the c2 and then execute them.


![String printed on successful connection](images/acim_botconnectstr.png)

Most working of  the malware is handled by main.AwaitCommands functions. It ensures that the connection is successful and patiently listens for incoming commands from the c2 and when a command is received it parses the command and executes the appropriate function.

main.AwaitCommands function starts with an infinite while loop inside which various features of malware are called. The malware offers http.get and http.post flood ddos attacks.
The check routines checks if the value of puVar3 is equal to 0x8 and *p1Var2 contains the string 0x7465672d70747468 i.e (http.get). Once that is done malware proceeds to further spawn several gorountines each one calls function simpleGet and it initiates a ddos attack on the specified website.

Malware has good logging facilities and prints on screen “HTTP FLOOD | Starting for”


![checking if the c2 command includes http.get](images/acim_calling_http_get.png)


Exactly the same approach is followed when the http.post method is required in order to conduct the ddos attack. The only difference is this time the check is for puVar3 is equal to 0x9 and *p1Var2 contains the string  http.post.


![checking if the c2 command includes http.post](images/acim_http_post.png)


Also the malware contains a third case which if comes true , it prints “Ping RecievedReset Content” on the screen.


![ping test](images/acim_ping_reset.png)

Further the main.AwaitCommands function is supported by other functions as shown and they do exactly what name.


The functions such as randomDigit, randomString, randonToken uses golang’s rand functions to seed the current time and then generate random integers. The implementation is trivial.
Functions such as SimpleGet and SimplePost are where actual http get/post requests are made using the golang net/http module.

## Network Table

Functions Making Network Connections Function | Purpose Of Connection
---|---
main.Connect() | Makes an Connection to the C2 Server
simpleGet() | Makes http get request in order to DDOS
simplePost() | Makes http post request in order to DDOS



The malware was nicely written and had good logging capabilities with limited functionalities for a ddos botnet malware. The Malware Author didn't bother to statistically compile the binary thus the malware will not work all linux distributions also lead to it having debug symbols attached to the binary making the analysis easy.The command and control server for this botnet was hosted in Germany. We believe newer and more sophisticated variants of this malware will pop up in future and removing them will not be so trivial thus patching of linux based systems is recommended.

# Indicator of Compromise

## IP’s Reached Out

+ 51.75.68.215

![nmap scan](images/acim_c2_open_ports.png)

## Command and Control Setup

![Command And Control Entire Scan](images/acim_c2_image.png)

# Mitigation Strategy and techniques

This attack is based on installing the malware on linux based systems and keep it hidden for long period of times thus for mitigations:

## Use The Following Yara Rule For Malicious Excel Document Detection

```
private rule is_executable
{
	condition:
		uint16(0) == 0x5A4D or uint32(0) == 0x464c457f or uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca
}

rule crime_ZZ_botnet_aicm
{
	meta:
		description = "DDoS Golang Botnet sample for linux called 'aicm'"
		sha256      = "496a46a07ae436b82b87bef642afbb3b06d9dbf0e0fae0199f6389f312fa4e57"

	strings:
		$a1 = "51.75.68.215:420"

		$f1 = "main.Connect" fullword
		$f2 = "main.AwaitCommands" fullword
		$f3 = "Methods.randomString" fullword
		$f4 = "Methods.randomDigit" fullword
		$f5 = "Methods.randomToken" fullword
		$f6 = "Methods.SimpleGet" fullword
		$f7 = "Methods.SimplePost" fullword

		$b1 = "/root/bot/Methods.userAgents\x00"
		$b2 = "/root/bot/bot.go\x00"
		$b3 = "Ping RecievedReset Content"
		$b4 = "[BOT] | Failed to connect, Retrying"
		$b5 = "HTTP FLOOD | Starting for "

		// Address 0x6409C2 in 'main.AwaitCommands'
		$opcodes_1 = {48 83 ?? 09 0F [3] 00 00 48 B? 68 74 74 70 2D [3] 48 39 ?? 0F }
		//  Address 0x640CDF in 'main.AwaitCommands'
		$weak_opcodes_1 = { 48 B? 68 74 74 70 2D 70 6F 73 48 B? 68 74 74 70 2D 67 65 74 }
		$weak_opcodes_2 = { 48 B? 68 74 74 70 2D 67 65 74 48 B? 68 74 74 70 2D 70 6F 73 }


		// Appear in 'Methods.SimplePost' and 'Methods.SimpleGet'
		$constant_1 = {80 7F B1 D7 0D 00 00 00}
		$constant_2 = {00 00 1A 3D EB 03 B2 A1}
		$constant_3 = {00 09 6E 88 F1 FF FF FF}
		$ua1 = "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3"
		$ua2 = "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1090.0 Safari/536.6"
		$ua3 = "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.120 Safari/535.2"
		$ua4 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6"
		$ua5= "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1"
		$ua6 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.27 (KHTML, like Gecko) Chrome/12.0.712.0 Safari/534.27"
		$ua7 = "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.15"
		$ua8 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36"
		$ua9 = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
		$ua10 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3191.0 Safari/537.36"
		$ua11 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2869.0 Safari/537.36"
		$ua12 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/532.5 (KHTML, like Gecko) Chrome/4.0.249.0 Safari/532.5"
		$ua13 = "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/532.9 (KHTML, like Gecko) Chrome/5.0.310.0 Safari/532.9"
		$ua14 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7"
		$ua15 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.14 (KHTML, like Gecko) Chrome/10.0.601.0 Safari/534.14"
		$ua16 = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.14) Gecko/20110218 AlexaToolbar/alxf-2.0 Firefox/3.6.14"
		$ua17 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML like Gecko) Maxthon/4.0.0.2000 Chrome/22.0.1229.79 Safari/537.1"

	condition:
		is_executable and (
			$a1 or 6 of ($f*) or 3 of ($b*) or all of ($ua*) or (
				any of ($b*) and (
					3 of ($f*) or
					$opcodes_1 or
					(for all of ($constant*): (# > 2))  or
					10 of ($ua*)
				) or
				any of ($weak_opcodes_*) and (
					(2 of ($f*) and (
						$opcodes_1 or 
						2 of ($constant*)
						)
					) or
					14 of ($ua*)
				)
			)
		)
}

```