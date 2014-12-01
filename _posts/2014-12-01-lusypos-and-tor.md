---
layout: post
title: "LusyPOS and Tor"
modified:
categories: 
excerpt: "A Blending of Dexter and Chewbacca"
tags: [POS, malware]
image:
date: 2014-12-01T09:53:10-05:00
---
By Nick Hoffman and Jeremy Humble

##Introduction

At our dayjobs, as reverse engineers at CBTS, Jeremy and I have been hunting new POS malware.  

A new sample appeared on Virustotal this week that had a very interesting name "lusypos.exe".  There have been very few references to this particular family and it appears to be fairly new.  Google searching was able to give me the following information:

<figure>
<img src="/images/lusypos_google.png">
</figure>

The sample that I'll be talking about in this post is bc7bf2584e3b039155265642268c94c7.  

At the time of this writing the malware is currently flagged on Virustotal by 7/54 engines.

<figure>
<img src="/images/lusypos_vt.png">
</figure>

Interestingly, some of the signatures seem to be hitting on the copy of tor.exe that is in the bundle.

<figure>
<img src="/images/lusypos_vt_vendors.png">
</figure>

##Analysis
This malware clocks in around 4.0 MB in size, so it's not small.  For comparison, getmypass POS malware was 17k in size.

The first thing of note when executing this in a sandbox is that this malware drops a copy of tor.exe, libcurl.dll, and zlib1.dll.  It also copies itself to the %APPDATA% directory on the victim host.  The following are the locations and MD5's of the dropped files are below:

The file mbamservice is the copy of tor.exe

{% raw %}
d0f3b3aaa109a1ea8978c83d23055eb1  C:\Documents and Settings\<USER>\Application Data\VeriFone32\libcurl.dll 
4407393c1542782bac2ba9d017f27dc9  C:\Documents and Settings\<USER>\Application Data\VeriFone32\mbambservice.exe
bc7bf2584e3b039155265642268c94c7  C:\Documents and Settings\<USER>\Application Data\VeriFone32\verifone32.exe
b8a9e91134e7c89440a0f95470d5e47b  C:\Documents and Settings\<USER>\Application Data\VeriFone32\zlib1.dll
{% endraw %}

The malware will also create the mutex "prowin32Mutex" and injects code into iexplore.exe.  This was a strange mix of dexter-like behavior mixed with Chewbacca-like techniques.

<figure>
<img src="/images/lusypos_procexp.png">
</figure>

While running in a sandbox, the malware communicated out to 

{% raw %}
86.59.21.38
212.112.245.170
128.31.0.39
154.35.32.5
193.23.244.244
{% endraw %}

Now let's get to the good stuff.  

###Decoding
The malware has an interesting method of decoding strings that are statically in the binary.

<figure>
<img src="/images/lusypos_decode.png">
</figure>

For the non-asm folks on here, the malware is using a lookup table with structures containing a one byte xor key, pointer to the string, and length of the string.  It will perform an additional xor operation at the end.

A decoder for this is written (in python below)

{% highlight python %}
{% raw %}
#!/usr/bin/env python
import sys
import struct
import binascii
import pefile

from pprint import pprint

class LusyEncodedString:
    
    def __init__(self,raw_data,file_content,pe):
        self.xor_key = struct.unpack('H',raw_data[0:2])[0]
        self.length = struct.unpack('H',raw_data[2:4])[0]
        self.virtual_offset = struct.unpack('I', raw_data[4:8])[0]
        self.raw_offset = pe.get_offset_from_rva(self.virtual_offset - pe.OPTIONAL_HEADER.ImageBase)
        self.encoded_str = file_content[self.raw_offset:self.raw_offset+self.length]
        self.decoded_str = ""

    def decode(self):
        for i in range(0,self.length):
            self.decoded_str += chr(ord(self.encoded_str[i]) ^ self.xor_key ^ i)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        d = {'xor key': hex(self.xor_key), 'length': self.length, 'raw offset': self.raw_offset,
             'virtual offset': self.virtual_offset, 'encoded string': self.encoded_str, 'decoded string': self.decoded_str}
        return str(d)
        
            
        
#For now we'll assume the table is always at RVA 401000 (raw 0x400) as hardcoded in bc7bf2584e3b039155265642268c94c7
# With a little more refinement this could be found dynamically
def parse_table(content,pe,table_rva=0x1000):
    encoded_strings = []
    raw_offset = pe.get_physical_by_rva(table_rva)   
    i = 0
    while True:
        raw_struct = content[raw_offset+i*8:raw_offset+i*8+8]
        # The last struct in the table is all null bytes. Stop parsing when we hit it
        if struct.unpack('<Q',raw_struct)[0] == 0:
            break
        else:   
            encoded_strings.append(LusyEncodedString(raw_struct,content,pe))
        i += 1
    return encoded_strings

if __name__ == '__main__':
    encoded_strings = []
    pe = pefile.PE(sys.argv[1])
    with open(sys.argv[1],'r') as fp:
        content = fp.read()
        encoded_strings = parse_table(content,pe,0x1000)
    
    for encoded_str in encoded_strings:
        encoded_str.decode()
        pprint(encoded_str.to_dict())

{% endraw %}
{% endhighlight %}

Which when executed will decode the following strings:

{% raw %}
http://kcdjqxk4jjwzjopq.onion/d/gw.php
http://ydoapqgxeqmvsugz.onion/d/gw.php
VeriFone32
verifone32
prowin32Mutex
b00n v1.1
\\Internet Explorer\\iexplore.exe
mbambservice.exe
tor.exe
zlib1.dll
libcurl.dll
Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations
Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0
LowRiskFileTypes
Content-Type: application/x-www-form-urlencoded
127.0.0.1:9050
Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0) g00n
curl_easy_init
curl_easy_setopt
curl_easy_cleanup
curl_easy_perform
curl_easy_strerror
curl_slist_append
curl_easy_getinfo
curl_slist_free_all
page=
&ump=
&ks=
&opt=
&unm=
&cnm=
&view=
&spec=
&query=
&val=
&var=
DetectShutdownClass
download-
update-
checkin:
scanin:
uninstall
response=
UpdateMutex:
Software\\Verifone32
Software\\Microsoft\\Windows\\CurrentVersion\\Run
.DEFAULT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
mbambservice.exe
wmiprvse.exe
LogonUI.exe
svchost.exe
iexplore.exe
explorer.exe
System
smss.exe
csrss.exe
winlogon.exe
lsass.exe
spoolsv.exe
alg.exe
wuauclt.exe
firefox.exe
chrome.exe
devenv.exe
{% endraw %}

This contains the C2 information, along with a process whitelist, and registry keys for persistence.  One thing to note based on these strings, is that it looks like the malware may have taken a queue from dexter.

###RAM Scraping
RAM scraping is performed through the common sequence of using CreateToolhelp32Snapshot, then using Process32First and Process32Next to iterate.  Pseudocode for that would look something like the following:

{% raw %}
handle = CreateToolhelp32Snapshot
Process32First(handle)
do 
	sleep 1000
	OpenProcess
	VirtualQueryEx
	ReadProcessMemory
 	CloseHandle
	Sleep 5000
while Process32Next
{% endraw %}

This technique is not new and is commonly used in many different POS Ram scrapers.  Truth is, that without writing a driver, the malware authors often have their hands tied and only have a few techniques to peer into process memory space.

###CC Validation
The malware also contains methods to search memory for sequences of data that look like credit card track information.

<figure>
<img src="/images/lusypos_regex.png">
</figure>

Once it finds that data, there are checks against the potential credit card number to determine if it is Luhn valid.  Luhn's algorithm is the defacto algorithm for validating credit card numbers.  It can be seen implemented in the malware using a lookup table rather than calcuating the digtial root.  One note, is that this is the same implementation of Luhn's as FrameworkPOS, Dexter, and getmypass.

<figure>
<img src="/images/lusypos_luhns.png">
</figure>

##Closing Thoughts
When looking into malware families like Chewbacca and now LusyPOS, one thought comes to mind.  Why would a POS machine be allowed to talk to tor?  Most PCI audits will attempt to lock this sort of activity down, but there seems to be devils in the implementation that allow malware like this to be successful.

This is just a scratch in the surface of a new malware family.  We'll be curious to watch it evolve over the next couple years and track its progress. 
