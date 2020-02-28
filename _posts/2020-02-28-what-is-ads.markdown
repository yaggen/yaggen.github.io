---
title: "What is Alternate Data Streams?"
date: 2020-02-28 22:56:44 +0000
categories:
  - blog
tags:
  - CTF
  - Forensics
  - ADS
  - English
---

# Introduction

Last day i was playing a "boot2root" CTF, and one of the most annoying parts was a 0-byte "empty" file appearantly containing an Alternate Data Stream (ADS). I had a hard time finding that the file contained an alternate stream, and an even harder time extracting the data contained in the stream. 

This was my first time stumbling upon an Alternate Data Stream (ADS)

Note that this was before i read up on ADS, and i was working at a Linux box at the time.

# What is ADS?

ADS is a file attribute in NTFS file systems, all files on NTFS contains atleast one data stream, the default one is called $DATA - for example a .txt file could (should) contain text in the $DATA stream but could also contain an image in an **Alternate Data Stream**.

![ADS PowerShell Example](https://jackhack.se/assets/images/ads_ps.png)

Example of viewing a file and all of it's streams with powershell, note that the file size appears to be 0 bytes.

Alternate data streams have previously been used by certain malwares to hide data during attacks, and there is also a couple of methods describing how to run executeables from an ADS stream.


Today it is possible to read and find files containing ADS, for example trough Windows Powershell or by using one of many available tools (Microsoft even providing a program called [streams](https://docs.microsoft.com/en-us/sysinternals/downloads/streams)).

# Solution

Eventually i switched to a Windows machine, since i knew the file originated from a Windows system. I tried running *type* and *more* on the file in the command prompt, somewhere here i heard about ADS and found a python library for handling alternate data streams on [GitHub](https://github.com/RobinDavid/pyADS). The file was placed on a SMB share and previously on this machine you were supposed to find multiple files on this very nested share, so i wanted to check all subfolders for any file containing additional streams and extract those streams. 

So i end up writing a very simple python-tool to do this.

~~~

import os
from pyads import ADS
path = '.'

streams = []
files = []
# r=root, d=directories, f = files
for r, d, f in os.walk(path):
    for file in f:
        files.append(os.path.join(r, file))

for f in files:
	handler = ADS(f)
	if handler.containStreams():
		for stream in handler.getStreams()[:]:
	# Zone.Identifier is a common ADS, containing information from where a specific file is downloaded.
			if stream == "Zone.Identifier": 
				continue
			print("Found ADS stream in following file:")
			print(f)
			print("Containing following stream:")
			print(stream)
			streams.append(f)
			choice = input("Do you want to extract streams? Y/N: ")
			if choice.upper() == "Y":
				fh = open(stream,"wb")
				fh.write(handler.getStreamContent(stream))
				print("Wrote stream to file: "+stream)
				fh.close()
			else:
				continue



~~~
{: .language-python}

*The tool with the necessary files can be found on my [GitHub](https://github.com/yaggen/adspy)*

So by mounting the SMB share to my Windows host, and running the script from the root of this share, i was now able to find and read the data streams.

![ADSpy SMB Example](https://jackhack.se/assets/images/ads_smb.jpg)

This was a first for me - to find a use case simple enough to write my own small script around, so with that in mind together with everything i learned about ADS and hacking Windows machines i really enjoyed this box! Except a writeut of the boox soon enough! 
