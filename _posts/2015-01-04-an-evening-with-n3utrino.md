---
layout: post
title: "An Evening With N3utrino"
modified:
categories: 
excerpt: A bot with credit card grabbing features
tags: [malware, POS]
image:
  feature:
date: 2015-01-04T12:59:26-05:00
---

##Introduction
In my previous post I showed off some tricks that malware authors use to check to see if they are being executed inside of a virtual machine.  While it was nothing new or groundbreaking, I consider it an interesting behavior to pivot off.  In some cases, depending on how the author searches for sandbox-like qualities, yara signatures can be generated looking for those techniques.

The piece of malware that I was looking at in the last post is fully featured and I thought that it might deserve another blog post.  Along with reversing some of the functionality, I'll also provide some detection strategies and signatures to help find this on a network.  There are other blog posts that talk about this particular family, but none of them seemed to talk much about the credit card dumping routines.

##Diving In
We'll start with the name.  Some malware likes to keep information about itself or the author behind it hidden.  On the other hand, other malware families contains gr33tz and banners declaring what it is and who wrote it.  

In this malware, a simple string is built with repeated 4 byte mov's.  

{% highlight bash %}
{% raw %}
00006430: c745f44e337574                   MOV DWORD [EBP-0xc], 0x7475334e
00006437: c745f872696e6f                   MOV DWORD [EBP-0x8], 0x6f6e6972
{% endraw %}
{% endhighlight %}

With a simple conversion

{% highlight bash %}
{% raw %}
echo '0x4e0x330x750x740x720x690x6e0x6f' | xxd -r 
N3utrino
{% endraw %}
{% endhighlight %}

In addition to the string "N3utrino", there are older samples that call out Neutrino in the User-Agent.

Good enough for me -- let's call it N3utrino or Neutrino.  

##Initial Chatter
When N3utrino attempts to connect, it will send out a packet with a payload of Ping=1 and expect a packet with a payload of "pong"  at this point communication will commence.  The session cookie is the md5 hash for the string "admin"

<figure>
<img src="/images/neutrino_ping.png">
</figure>

After this response is recieved the malware will send out some cursory information about the machine that it's running on.  Including serial number and if it's behind a NAT

<figure>
<img src="/images/neutrino_getcmd.png">
</figure>

There is more information endoded in the getcmd reply that relates to commands and what the botnet is instructed to do.  Those have been discussed in other blogs and will probably be redundant information here.  

##Scraping Credit Card Information
N3utrino features a pretty fully featured credit card scraping algorithm.  When looking at POS malware all of them seem to use the same handful of techniques.

The malware will use CreateToolhelp32Snapshot/Process32First/Process32Next to iterate over the processes, then a combination of OpenProcess -> VirtualQueryEx -> ReadProcessMemory to pull the contents of memory.  The pseudo-code is shown below.  

<figure>
<img src="/images/neutrino_memory.png">
</figure>

In addition, the program does whitelist the following processes:

* System
* smss.exe
* csrss.exe
* winlogon.exe
* lsass.exe
* spoolsv.exe
* devenv.exe

All of this is handed to a function that is responsible for parsing out track data.

The function that scans the memory then searches for track data. There are small functions that check character boundries to look for anything between 0 and 9.

<figure>
<img src="/images/neutrino_0_9.png">
</figure>

There are other functions to look to validate that what they are looking at it the name section of the track data.

<figure>
<img src="/images/neutrino_name.png">
</figure>

All of the potential hits are validated with Luhn's algorithm (using a lookup table) and passed on to a function that will exfil the data via a HTTP POST.

For reference, track data looks like the following (borrowed from the XyliBox blog)

~~~
Example of Track1: B4888603170607238^Head/Potato^050510100000000001203191805191000000 
Example of Track2: 4888603170607238=05051011203191805191
~~~

Once this data is captured, the following query string is built that will be used to connect to the C2.

The beacon will look like the following:

<figure>
<img src="/images/neutrino_cc_beacon.png">
</figure>


It's easy to see how the information is encoded. A simple base64 decode will reveal our initial data.

{% highlight bash %}
{% raw %}
echo "JUI0ODg4NjAzMTcwNjA3MjM4XkhlYWQvUG90YXRvXjA1MDUxMDEwMDAwMDAwMDAwMTIwMzE5MTgwNTE5MT8=" | base64 -d 
%B4888603170607238^Head/Potato^050510100000000001203191805191?
{% endraw %}
{% endhighlight %}

The credit card stealing section of Neutrino isn't one of the newest features, but it wasn't present in early builds.  The botnet is fully capable with other commands, but this will certainly draw additional value to the botnet operators and give them a secondary source of income on the black market.

##Changing Over Time

Below is a table where I tracked a handful of samples. It's interesting to watch it grow over time.  This is by no means fully comprehensive.  Some of the samples don't have mutexes associated with them; this is a result of not having time to dig them all out.

| Hash | Size | Compiled | Mutex      | User Agent  |
| ---  | ---  | ---      | ---        | ---         |
| bb42fce5d9cb73561ec4e3c343c10d52 | 37888 | 2014:03:28 10:31:09-04:00 | n3nmtx                    | Neutrino/2.1 | 
| e43b206fae0b842feeac87f682a791d9 | 37376 | 2014:03:31 13:27:52-04:00 | n3nmtx/protected_n3utrino | Neutrino/2.1 | 
| e1383bea710422248b7e1edc4e0ff6ec | 37376 | 2014:04:01 14:47:58-04:00 | n3nmtx/protected_n3utrino | Neutrino/2.1 |
| 833afb2bf357198ad5c442e396642b7c | 53248 | 2014:08:13 09:59:18-04:00 | | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 |
| 35e2ef3c45ebde10089a1b338a5de72c | 48128 | 2014:09:18 18:22:33-04:00 | | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 |
| 12c01123ac54a6ac872ee55cd217b56b | 69632 | 2014:09:19 20:45:40-04:00 | | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 |
| 55c105428c6c9141551ec517fa439e6e | 48128 | 2014:09:19 20:45:40-04:00 | | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 | 
| 7ad1b14e50418acf3a3a0caaecbdc885 | 49152 | 2014:09:19 20:45:40-04:00 | | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 | 
| 6b6c452d3b2e12001deaefae7a5bc277 | 62976 | 2014:09:24 19:04:25-04:00 | | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 | 
| de1af0e97e94859d372be7fcf3a5daa5 | 64512 | 2014:10:10 22:26:56-04:00 | | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 | 
| a2638e21c286976c9626df3ff7b1423b | 64512 | 2014:10:10 22:31:17-04:00 | | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 | 
| 54108dff06db6f106af6d3f9c8aa06d0 | 87040 | 2014:11:09 02:27:02-05:00 | | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 | 
| ecf11e76eba7dc9462cf238e27e6564b | 87040 | 2014:11:10 15:07:34-05:00 | | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 |
| 1b77492456d1a38f8c3bd7757df959cd | 90112 | 2014:11:10 15:07:34-05:00 | | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 | 
| 62b3008e87647af5b8e4aff42cedc6cd | 88064 | 2014:11:21 13:37:27-05:00 | | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 | 
| 1b0e085c72c5294041bcb24f48f2f75f | 93184 | 2014:11:30 20:02:26-05:00 | 2747744-NN | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 | 
| ae9c4ccee7c5738750f167e494ceab6b | 95744 | 2014:12:18 11:26:51-05:00 | 4ZM059116-NN | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 | 
| 7c92382f92f7367310dd4acdc2fc5a80 | 95744 | 2014:12:19 15:51:46-05:00 | 4ZM059116-NNIF | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 | 
| 1da58eca56e42b4240ae79c8829b62cd | 92672 | 2014:12:26 16:01:28-05:00 | 4MPMMXI-NIF | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 |
| ccbf7cba35bab56563c0fbe4237fdc41 | 95232 | 2014:12:31 09:47:27-05:00 | MLVSSI-DUPPO | Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0 | 

I've posted a majority of these up to totalhash.com if anyone would like to look at them further.  Some of them will need manual patching to execute properly in a sandbox.

##Detecting
Searching for command and control sites is weak at best.  Botnets like N3utrino are known for burning and changing infrastructure as they are discovered or blocked.  However the following signatures should be able to help find these on your network.

###Bro
Using the following Bro signatures should assist in finding this on your network. These could be easily converted to snort signatures if that is more applicable to your environment.

{% highlight ruby %}
{% raw %}
signature n3utrino-checkin {
    #Author = Nick Hoffman
    #Ref: securitykitten.github.io
    ip-proto == tcp
    dst-port == 80
    payload /.*ping=1/
    event "N3utrino check in"
}

signature n3utrino-sendinfo {
    #Author = Nick Hoffman
    #Ref: securitykitten.github.io
    ip-proto == tcp
    dst-port == 80
    payload /.*getcmd\=1\&uid\=.*\&os\=.*\&av\=.*\&nat\=.*\&serial\=.*\&quality\=.*/
    event "N3utrino POST host information"
}

signature n3utrino-sendCCInformation {
    #Author = Nick Hoffman
    #Ref: securitykitten.github.io
    ip-proto == tcp
    dst-port == 80
    payload /.*dumpgrab\=1\&track_type\=.*\&track_data\=.*\&process_name\=.*/
    event "N3utrino POST CC information"
}

signature n3utrino-tasks {
    #Author = Nick Hoffman
    #Ref: securitykitten.github.io
    ip-proto == tcp
    dst-port == 80
    payload /.*(taskfail|taskexec)\=1\&task_id\=[0-9]{10,}/
    event "N3utrino POST taskfail and taskexec"
}
{% endraw %}
{% endhighlight %}

To validate these signatures are working, a simple command can be ran against a pcap.

{% highlight bash %}
{% raw %}
 bro -s neutrino.sig -r cap.pcapng
{% endraw %}
{% endhighlight %}

Then the results in notice.log


~~~
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	suppress_for	dropped	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	interval	bool	string	string	string	double	double
1420232158.228817	CrWEBe3Jp2hpqAQCY6	10.0.2.15	1036	198.12.95.66	80	--	-	tcp	Signatures::Sensitive_Signature	10.0.2.15: N3utrino check in	POST /admin/tasks.php HTTP/1.0^M^JHost: stormstresser.net^M^JUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28....	10.0.2.15	198.12.95.66	80	-	bro	Notice::ACTION_LOG	3600.000000	F	-	-	-	-	-
1420232158.480959	CxJ5Fb4mNjXdZ5P441	10.0.2.15	1037	198.12.95.66	80	--	-	tcp	Signatures::Sensitive_Signature	10.0.2.15: N3utrino POST host informationPOST /admin/tasks.php HTTP/1.0^M^JHost: stormstresser.net^M^JUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28....	10.0.2.15	198.12.95.66	80	-bro	Notice::ACTION_LOG	3600.000000	F	-	-	-	-	-
1420232185.366933	CjOekl2fPicVQcSoZd	10.0.2.15	1039	198.12.95.66	80	--	-	tcp	Signatures::Sensitive_Signature	10.0.2.15: N3utrino POST taskfail and taskexec	POST /admin/tasks.php HTTP/1.0^M^JHost: stormstresser.net^M^JUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28....	10.0.2.15	198.12.95.66	80	-	bro	Notice::ACTION_LOG	3600.000000	F	-	-	-	--
1420232218.524922	CovCPx2pn1dy806Xn7	10.0.2.15	2538	198.12.95.66	80	--	-	tcp	Signatures::Sensitive_Signature	10.0.2.15: N3utrino POST host informationPOST /admin/tasks.php HTTP/1.0^M^JHost: stormstresser.net^M^JUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28....	10.0.2.15	198.12.95.66	80	-bro	Notice::ACTION_LOG	3600.000000	F	-	-	-	-	-
1420232254.005793	C0Ck1I365Xn0iBkRu	10.0.2.15	2812	198.12.95.66	80	--	-	tcp	Signatures::Sensitive_Signature	10.0.2.15: N3utrino POST taskfail and taskexec	POST /admin/tasks.php HTTP/1.0^M^JHost: stormstresser.net^M^JUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28....	10.0.2.15	198.12.95.66	80	-	bro	Notice::ACTION_LOG	3600.000000	F	-	-	-	--
1420232254.127819	CgM16e3DiOZcKDI9D7	10.0.2.15	2813	198.12.95.66	80	--	-	tcp	Signatures::Sensitive_Signature	10.0.2.15: N3utrino POST taskfail and taskexec	POST /admin/tasks.php HTTP/1.0^M^JHost: stormstresser.net^M^JUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28....	10.0.2.15	198.12.95.66	80	-	bro	Notice::ACTION_LOG	3600.000000	F	-	-	-	--
1420232276.187667	COWwMqI98q7gSz4al	10.0.2.15	2816	198.12.95.66	80	--	-	tcp	Signatures::Sensitive_Signature	10.0.2.15: N3utrino POST taskfail and taskexec	POST /admin/tasks.php HTTP/1.0^M^JHost: stormstresser.net^M^JUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28....	10.0.2.15	198.12.95.66	80	-	bro	Notice::ACTION_LOG	3600.000000	F	-	-	-	--
1420232276.523710	CgBjGe17rI5pNTiVHe	10.0.2.15	2817	198.12.95.66	80	--	-	tcp	Signatures::Sensitive_Signature	10.0.2.15: N3utrino POST host informationPOST /admin/tasks.php HTTP/1.0^M^JHost: stormstresser.net^M^JUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28....	10.0.2.15	198.12.95.66	80	-bro	Notice::ACTION_LOG	3600.000000	F	-	-	-	-	-
1420232298.032527	CnVd1qmAmPgq7y5Pl	10.0.2.15	2889	198.12.95.66	80	--	-	tcp	Signatures::Sensitive_Signature	10.0.2.15: N3utrino POST taskfail and taskexec	POST /admin/tasks.php HTTP/1.0^M^JHost: stormstresser.net^M^JUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28....	10.0.2.15	198.12.95.66	80	-	bro	Notice::ACTION_LOG	3600.000000	F	-	-	-	--
1420232304.108335	CSqT1o1WThet5Hsui9	10.0.2.15	2890	198.12.95.66	80	--	-	tcp	Signatures::Sensitive_Signature	10.0.2.15: N3utrino POST CC information	POST /admin/tasks.php HTTP/1.0^M^JHost: stormstresser.net^M^JUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28....	10.0.2.15	198.12.95.66	80	-bro	Notice::ACTION_LOG	3600.000000	F	-	-	-	-	-
#close	2015-01-03-15-59-15
~~~

###Yara
In addition to network signatures, N3utrino can be caught at the host level with the following rules.  This is a very simple rule but should suffice for the versions discussed in this post.  Diving down into each function would yield in higher fidelity signatures, but we'll save that as an excersise for another blog post.

~~~
rule N3utrino
{
    meta:
        Author = "Nick Hoffman"
        Description = "Detects versions of Neutrino malware"

    strings:
        $post_host_information = "getcmd=1&uid=%s&os=%s&av=%s&nat=%s&version=%s&serial=%s&quality=%i"
        $post_cc_information = "dumpgrab=1&track_type=%s&track_data=%s&process_name=%s"
	$post_taskexec = "taskexec=1&task_id=%s"
	$post_taskfail = "taskfail=1&task_id=%s"
	
        $command1 = "loader"
        $command2 = "findfile"
        $command3 = "spread"
        $command4 = "archive"
        $command5 = "usb"
        $command6 = "botkiller"
        $command7 = "dwflood"
        $command8 = "keylogger"
    condition:
		4 of ($command*) or any of ($post*)
}
~~~

##Other Research
There have been a couple other articles that mention Neutrino/N3utrino.  Some in greater detail than others.  For anyone interested, here's some nice reading:

* [McAfee](http://blogs.mcafee.com/mcafee-labs/glance-neutrino-botnet)
* [badtrace.com](http://blog.badtrace.com/post/analysis-of-win32-n3nmtx-trojan/)


##Conclusion
At first glance it's easy to write off a botnet as "run of the mill" malware and not take a deeper dive.  Chasing down some of the functions inside of N3utrino not only allowed us a better understanding of what exactly it does, but the tricks it has up its sleeve to evade simple detection.  Using these strategies we can write rules that detect N3utrino and hopefully will keep detecting it through many iterations.
