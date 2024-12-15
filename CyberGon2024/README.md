# Digital Forensics

## Badboy

## Badboy1

Inside `/Users/testing/Downloads/backupemls` directory, there are multiple email file. After reviewing each file individually, We got 2 suspicious email that contains QR code

First email:
![image](https://hackmd.io/_uploads/S133erimye.png)

Second email:
![image](https://hackmd.io/_uploads/SJ5qeHiXkl.png)

If we scan that QR code, it will redirect us to a malicious website which if accessed will directly download malware to our device

This method is called QR Phishing or `Quishing`. And then if we check the email header, we got the email service name which is `emkei.cz`

```
[SNIP]
Received-SPF: None (protection.outlook.com: movietheratre.com does not
 designate permitted sender hosts)
Received: from emkei.cz (114.29.236.247) by
 CH1PEPF0000AD83.mail.protection.outlook.com (10.167.244.85) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8182.16
 via Frontend Transport; Wed, 27 Nov 2024 16:13:39 +0000
[SNIP]
```

Flag: `CYBERGON_CTF2024{emkei_quishing}`

## Badboy2

We download the malicious file into the `/Users/testing/Downloads` directory, and then we upload it to VirusTotal:

https://www.virustotal.com/gui/file/fe321e33dd29bcc7dba51d40283cde9f3cb7bc50cb1b3674387f4dfbc93c7d18/details

First, we got the original filename which is `ab.exe`

![image](https://hackmd.io/_uploads/ByD_Erj7yx.png)

Second, we got the SHA1 hash in VirusTotal `details` tab

![image](https://hackmd.io/_uploads/H1yFBBsmJg.png)

Third, we got the IP:PORT was used to download from the QR code which is `192.168.1.49:8080`

```
daffainfo@dapOS:~$ curl 'https://qr.codes/1iHgbm' -I
HTTP/2 302
date: Mon, 02 Dec 2024 14:15:10 GMT
content-type: text/html; charset=UTF-8
location: http://192.168.1.49:8080/MovieTheratre.exe
[SNIP]
```

Flag: `CYBERGON_CTF2024{ab.exe_d87d087f87650f8ef030728160ec445160884c51_192.168.1.49:8080}`

## Warm Up

For this challenge we have to look up the timezone of the device, we can search this information using `SYSTEM & SOFTWARE` registry. First of all we look up in this path of SYSTEM registry `SYSTEM\ControlSet001\Control\TimeZoneInformation` to find out the time zone 

`SYSTEM\ControlSet001\Control\TimeZoneInformation`
![image](https://hackmd.io/_uploads/BkBxTL671g.png)

after that we have to search up the software timezone databases that related to Singaporean Time zone in the `SOFTWARE` Registry in this path. 

`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\Singapore Standard Time`
![image](https://hackmd.io/_uploads/ryK6T86Q1x.png)

CYBERGON_CTF2024{UTC+08:00 Kuala Lumpur, Singapore}


## DFIR (1)

In this challenge, we have to look up after the device hostname and device owner's username. In this case, we can search that information on the registry, specifically in the `SYSTEM` registry. Before i search it, i load all the log file of that registry so it can be clean when we load into registry explorer. proof below:

![2_systemClean](https://hackmd.io/_uploads/HJB_yB6Xkx.png)

To search the hostname/computername information in that registry, we can search it in this path`[ROOT]/ControlSet/Control/ComputerName/ComputerName`. As we can see below image that the Computer Host Name is WHITE-PARTY 

![2_computerName](https://hackmd.io/_uploads/HkBu1H6Xyg.png)

Next on, we have to seach the username of the devices, we can easily search it in the users directory and the directory name in it is the asnwer. Proof below 
![2_Username](https://hackmd.io/_uploads/rkHO1S67yl.png)

Flag: `CYBERGON_CTF2024{WHITE-PARTY, Sean John Combs}`

## DFIR (2)

For this challenge, we have to search about the device's owner facebook id, for searching this facebook id, after analyzing the file, we found out that the user open the facebook through the web application. For website analysis in the disk image file we can focus on the `USERS/[selectedUsers]/AppData/Local/[broswerName]`. First of all, we analyzing the cache file of each broswer directory using `NirSoft CacheFileViewer` and we can sure that it can be for checking the users visited urls. Proof below: 

![chromesuccess](https://hackmd.io/_uploads/HJt0fLTm1g.png)

But when we trace all of that, we cant parse the mozilla cache data entries. And from here we dumpp of all the mozilla directory and analyzing manual using grep command in linux. Proof below

![entriesfailed](https://hackmd.io/_uploads/ryRoz86mke.png)

before that, we do some research that facebook have its own templating for the users profile. We found it like this.

![idexplain](https://hackmd.io/_uploads/BkCoz86X1l.png)

because of that, we can use grep command to search about that facebook id in the mozilla directory. using this command:

```shell
grep -air facebook.com |  grep -E '[0-9]{14}'
```

the first grep command search all recursively with case insensitive and match binary file that contain word "facebook.com" and the second grep command is activate the regex function in regex that search numeric value with 14 digits of numbers. After do some try and error we found the correct id and his profile page. Proof below:

![stringsgrepfacebook](https://hackmd.io/_uploads/SkRszUTXJg.png)
![diddyfacepage](https://hackmd.io/_uploads/r1mcZUamke.png)

Flag: `CYBERGON_CTF2024{61567849079733, East Coast Rapper}`

## DFIR (3)

In this challenge we need to know the owner's nickname. When we analyze this .ad1 file, we notice that the owners nickname rely with Windows Security Question in the registry. If we use autopsy for analyzing it can be seen OS Account detail -> Host detail and already got the answer. 

![3_secQuesAutpsy](https://hackmd.io/_uploads/By115A5X1g.png)

but if we use ftk imager we need to extraxct `SAM registry hive`, open it with registry explorer and search that value in this path `SAM\Domains\Account\Users` 
![image](https://hackmd.io/_uploads/HkrsqAqX1l.png)

Flag: `CYBERGON_CTF2024{Ko Toke Gyi}`


## DFIR (11)

In this challenge, we need to find the flag based on the owner's facebooks's friend post that posting about him. So in this case we can check through the owner's facebook page that we already got previously and check the friend's tab -> following. 

![4_followingPage](https://hackmd.io/_uploads/SJmzRC57Jl.png)

After search it, the whole following friend, we got something interesting with this account [link](https://www.facebook.com/Lwaneainko). Refer to this post, [Link](https://www.facebook.com/share/p/1EjRWT2jBK/)
and from that post, we analyze it and found the flag rely in the post edit history. Even though there are some fake flag, we noticed that the real flag was in the same format as before. 

![image](https://hackmd.io/_uploads/rJ43gysmke.png)


Flag: `CYBERGON_CTF2024{s0c14L_m3d14_O51n7!!!!!}`