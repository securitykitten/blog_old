---
layout: post
title: "The Little Dumper That Could"
modified:
categories: 
excerpt: A 4k Credit Card Dumper
tags: [malware, POS]
image:
  feature:
date: 2015-01-30T14:32:54-05:00
---

##Introduction

I've recently been doing a lot of work around credit card dumpers at CBTS.  While casually browsing through totalhash I found the following binary (http://totalhash.com/analysis/1c8bae904340f9a8cf17d90a2de726a226ad6dba) that contained some interesting strings.  The one thing that stood out to me was its size and detection ratio.  This binary clocked in at only 4k and scored a rough 7/51 on Virustotal.

<figure>
<img src="/images/little_vt.png">
</figure>


##Diving In

This malware does not take its time to get started.  The very first API call is to CreateToolhelp32Snapshot, followed by a call to Process32First.  This is a telltale sign of iterating over the running processes on a host.

<figure>
<img src="/images/little_first_ins.png">
</figure>


The malware then checks the process name against a small whitelist of the following programs.  

<figure>
<img src="/images/little_whitelist.png">
</figure>


If the program is in the whitelist, a flag is set and the malware will iterate to the next process by calling Process32Next.  If the process is not in the whitelist, the malware will obtain a handle by calling OpenProcess and then ReadProcessMemory to read into the memory space.  The next functions are searching for Track 1 and Track 2 data.

<figure>
<img src="/images/little_readprocessmemory.png">
</figure>


The function that is searching for track 1 data simply looks for a “B” (leading sentinel in track 1 data) and then a handful of nested conditional statements checking for numbers between 0 and 9.  After some basic bounds checking, if the '^' is found (which is the separator for track 1 data) it is assumed that a credit card number has been found and the output is displayed in a message box.

<figure>
<img src="/images/little_track1.png">
</figure>


The track 2 data hunt section works in much the same way -- this time looking for '=' and '?'.

<figure>
<img src="/images/little_track2.png">
</figure>


Once all processes are iterated, the program closes.

Running this program in a sandbox and preloading track data into Notepad will produce the following output.

<figure>
<img src="/images/little_sandbox.png">
</figure>

<figure>
<img src="/images/little_sandbox1.png">
</figure>


This program is likely a proof of concept or just an author testing some code for demonstration.  It's unlikely that a malware author would display track information up in a MessageBox.  

##Conclusion

This malware is not the next biggest thing, nor is it exciting and new.  This malware highlights that you don't need to be innovative or unique to create a simple tool that can go undetected by a majority of AV vendors.

A common mistake made by malware authors is compiling unnecessary code into their programs.  I previously documented the functionality of the Mozart and Getmypass credit card dumpers.  These programs went notoriously undetected for some time.  Mozart eventually led to one of the most high profile breaches of the last several years.  The one thing these tools had in common is that they were small, functional, and they didn't include unnecessary overhead.  

Getmypass was scoring 0/55 on Virustotal when it was discovered; Mozart (when first uploaded to Virustotal) scored 5/56.  These tools were simply tools.  They didn't feature C2 functionality, they didn't keylog, and they didn't do anything that would otherwise set off alarms.  By keeping their focus tight they were able to be extremely successful and evade detection.
