---
layout: post
title: "VM Checking and Detecting"
modified:
categories: 
excerpt: A look at checks in a modern piece of malware
tags: []
image:
  feature:
date: 2014-12-02T20:34:49-05:00
---

##Introduction

I recently noticed a new piece of malware that had made its way into the database.  The part that stuck out to me is that it runs checks to ensure that it's not being debugged or running in a sandbox.  While this is not a new trick by any means, it is something that I haven't seen in a while.  Let me explain.

A handful of years ago, many big companies started investing money in virtual desktop solutions to combat malware and protect their employees from highly vulnerable attack vectors, such as web browsing and email.  As a result of this, many of the malware authors started to remove VM checking code from their malware samples.  Running in a virtual machine (if it's one somebody was using as a desktop) is now OK.

The modern trend is to try and look for specific security tools or automated sandboxes, rather than asking the generic question "am I running in a virtual machine?"  There have been several well written posts about this topic. Some notable ones are 

* [joe4security](http://joe4security.blogspot.com/2012/08/vm-and-sandbox-detections-become-more.html)
* [slideshare](http://www.slideshare.net/mnajem/malware-detection-with-multiple-features)
* [fireeye](http://www.fireeye.com/resources/pdfs/fireeye-hot-knives-through-butter.pdf)
* [codeproject](http://www.codeproject.com/Articles/9823/Detect-if-your-program-is-running-inside-a-Virtual)

I thought it would be useful to step through a piece of current malware and understand what's being used in the wild.  We'll also write some yara rules that will help look for this sort of activity. 

The malware that I'll be looking at in this report is  md5sum:de1af0e97e94859d372be7fcf3a5daa5 

Fortunately for us, all the anti-sandbox functionality is wrapped into one big function that does each check one at a time and exits the process if the checks fail.  In order, the malware will do a check for:

* Checking the sleep command
* Check IsDebuggerPresent and CheckRemoteDebuggerPresent
* Check the username and file path
* Check for wine
* Check for Specific Dll's
* Check VMWare
* Check VBox
* Check QEMU
* Check Drive Size

One nice thing about having all this functionality in one method is that we can simply patch over the entire method when trying to debug the binary.  If these checks were peppered through the malware it would be much more difficult to find them all and patch them. 

###Sleep Checking
Stepping into the first function, the check for sleep looks like the following 

<figure>
<img src="/images/antivm_check_sleep.png">
</figure>

Which calls GetTickCount, sleeps for 500 milliseconds, then GetTickCount again.  It takes the difference from the two counts and if it's greater than 450 milliseconds the test passes.  This check would prevent the analyst from patching sleep to a RETN 4 or from hooking the sleep function.

###Check Debugger
The next test check 2 API's to check for the presence of a debugger 

The first for IsDebuggerPresent
<figure>
<img src="/images/antivm_check_debugger.png">
</figure>

The second for CheckRemoteDebuggerPresent
<figure>
<img src="/images/antivm_check_remotedebugger.png">
</figure>

###Check Users
After the debugging checks, it will check the username on the machine.  The code does this by calling GetUserNameA

<figure>
<img src="/images/antivm_check_username.png">
</figure>

It will then convert this to uppercase

<figure>
<img src="/images/antivm_check_toupper.png">
</figure>

It'll take the result of this string and check it against the following names:

* MALTEST
* TEQUILABOOMBOOM
* SANDBOX
* VIRUS
* MALWARE

As shown in the code below:

<figure>
<img src="/images/antivm_check_maltest.png">
</figure>

And checking the other names

<figure>
<img src="/images/antivm_check_othernames.png">
</figure>

###Check File Path
The next check looks at the file path to see if it contains popular sandbox mount points or folders.  The malware achieves this by calling GetModuleFileNameA, toupper the result and then checking against the following strings

* \\SAMPLE
* \\VIRUS
* SANDBOX

<figure>
<img src="/images/antivm_check_path.png">
</figure>

###Check for Wine
The next piece of code will check for the existence of wine running on the machine.  This is achieved by checking if kernel32.dll contains the export "wine_get_unix_file_name"

<figure>
<img src="/images/antivm_check_wine.png">
</figure>

###Check Loaded DLL's
After the wine check the malware will search for the following dlls loaded by calling GetModuleHandleA

* sbiedll.dll  (Sandboxie) 
* dbghelp.dll  (vmware) 
* api_log.dll   (SunBelt SandBox) 
* dir_watch.dll  (SunBelt SandBox) 
* pstorec.dll  (SunBelt Sandbox) 
* vmcheck.dll  (Virtual PC) 
* wpespy.dll  (WPE Pro)

Other sandboxes will be caught by this in addition to the ones in parentheses.

<figure>
<img src="/images/antivm_check_dlls.png">
</figure>

Oddly enough, when this check completed, it'll look again for wine using the same code as above.  I'm assuming this is author error.

###Check VMWare
After the second check for wine occurs the malware will look for VMWare by checking the following registry key "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" with the value of Identifier and the data of "VMWARE"

<figure>
<img src="/images/antivm_check_vmware.png">
</figure>

<figure>
<img src="/images/antivm_check_vmware_1.png">
</figure>

Another check after this one will check for the existence of the key "SOFTWARE\\VMware, Inc.\\VMware Tools" which is looking for existence of vmware tools being installed on the system.

<figure>
<img src="/images/antivm_check_vmware_tools.png">
</figure>

###Check VBox
After the checks for the VMware, the malware will now look for evidence of VirtualBox through the existence of some registry keys.  Similar to the VMWARE check, the malware will search for the key "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" with the value of "Identifier" and the data of "VBOX"  The first half of this function is identical to the VMware check that happened earlier.

<figure>
<img src="/images/antivm_check_vbox.png">
</figure>

The next VirtualBox check will look for a different key.  "HARDWARE\\Description\\System" with a value of "SystemBiosVersion" and data of "VBOX"

<figure>
<img src="/images/antivm_check_vbox_system.png">
</figure>

<figure>
<img src="/images/antivm_check_vbox_str.png">
</figure>

This is followed by a check for GuestAdditions via a registry entry.  "SOFTWARE\\Oracle\\VirtualBox Guest Additions"

<figure>
<img src="/images/antivm_check_vbox_guest.png">
</figure>

Another VirtualBox check happens by looking for the video drivers.  This happens again via the registry looking for the key "HARDWARE\\Description\\System" with value of "VideoBiosVersion" and data of "VIRTUALBOX"

<figure>
<img src="/images/antivm_check_vbox_video.png">
</figure>

<figure>
<img src="/images/antivm_check_virtualbox.png">
</figure>

This wraps up the checks for VirtualBox. Now the malware will check for the existence of QEMU. 

###Check QEMU
Hunting for QEMU is almost identical to the methods used when searching for VBox.  The first check is a look at the registry key "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" with the value of "Identifier" and the data of "QEMU".

<figure>
<img src="/images/antivm_check_qemu.png">
</figure>

<figure>
<img src="/images/antivm_check_qemu_1.png">
</figure>

The next QEMU check is checking against the reg key "HARDWARE\\Description\\System" with a value of "SystemBiosVersion" and data of "QEMU".

<figure>
<img src="/images/antivm_check_qemu_2.png">
</figure>

<figure>
<img src="/images/antivm_check_qemu_3.png">
</figure>

###Drive Size Check
Now that the malware is finished checking registry keys it will do a final audit to figure out the drive size.  There are a variety of ways that malware can accomplish this, but this particular sample is using DeviceIOControl.  The first thing that it does is get a handle to PhysicalDrive0 via CreateFileA.

<figure>
<img src="/images/antivm_check_phycheck.png">
</figure>

It will then use the returned handle and pass it to DeviceIOControl with the dwIOControlCode 7405C (IOCTL_DISK_GET_LENGTH_INFO)

<figure>
<img src="/images/antivm_check_phycheck_1.png">
</figure>

It will take the output of this function and divide it by 1073741824 to get the size of the drive in gigabytes.  The size of the hard drive is then checked against the value of 10. If the drive is smaller, then the malware will halt execution.

<figure>
<img src="/images/antivm_check_phycheck_2.png">
</figure>

###Finding this Activity
Looking for this behavior is not that difficult with a combination of a handful of yara rules.  Without going into the detail of each one, I've just uploaded them all to github.  Feel free to modify and use these any way you like.  If you have any useful additions, please contribute!

[https://github.com/securitykitten/public_yara_rules](https://github.com/securitykitten/public_yara_rules)

##Online Source
A while back ago, I found a chunk of code in which the author made a little vm-checking class.  It has all the standard checks and some of the ones that we discussed in this post.

{% gist securitykitten/26a326908d6f18170229 %}

##Conclusion
While this is not a new tactic, it's interesting to see that some malware authors are still concerned with writing VM resistant code.  There is a shift toward avoiding sandbox technology and while this malware does display that activity, it also has broader checks that look for generic evidence of a VM.
