---
layout: post
title: "Finding Beacons With Bro"
modified:
categories:  
excerpt:
tags: [bro, malware, hunting]
image:
  feature:
date: 2015-07-01T22:01:01-04:00
---

##Introduction

I'll keep this one short.  I've recently been spending more time with the Bro framework and discovering the power of its scripting language.  I had written a PoC [script](https://code.google.com/p/lightbulb/) around using entropy to find beacons in network traffic.  The script grew and matured over the years, but there eventually became a need to run this against live network traffic and not just logs.

Enjoy the script and commit a change.  It's a little memory heavy at the moment, due to the use of a global hash.  This can be resolved by replacing the hash with a tree.

{% gist securitykitten/a7edcee0932c556d5e26 %}
