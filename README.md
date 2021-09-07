<p align="center">
    <img src="PikachuScan.png" alt="Pikachu is not here" width="300" height="370" align="center">
<p/>

## Starting & Disclaimer

PikachuScan is a small and powerful tool that can scan every port (0-65535) in just seconds. It uses threads efficiently for speed and avoids any errors while creating too many threads. Note that this will not perform stealth scan (like in Nmap) because it uses the connect method inside the socket module to properly implement the TCP connect (3-way handshake). But you can use the `-n` option to achieve this (SYN-ACK) by the Nmap module. Also, you can hide your IP address by using the `-r` option to scan your target with tor.

## Features

- Input IP/Domain in whatever format you like
- Exclude any IP/Domain from the scan
- Can read IP/Domain from the specified file
- By file, you can decide which file will include or exclude in the scan
- Define whatever port you like
- Define any port range
- Can select any port with port range
- Tor for anonymity
- Nmap module for stealth scan

## Installation

```shell
git clone https://github.com/darkmatter-index/PikachuScan.git && cd PikachuScan
```

Clone the repository and go to **PikachuScan** directory

```shell
python3 -m pip install virtualenv
```
Install the **virtualenv**

```shell
python3 -m virtualenv PikachuScanVenv
```
Create the virtual environment named **PikachuScanVenv**

```shell
source PikachuScanVenv/bin/activate
```
Activate the **PikachuScanVenv** virtual environment

```shell
python3 -m pip install -r requirements.txt
```
Install all the requirements of the **PikachuScan** tool

```shell
chmod u+x PikachuScan.py
```
Give execute permission to **PikachuScan.py**

```shell
python3 ./PikachuScan.py
```
Launch it!

## Specification

```
  
[ Domain ]

 Ex: example.com
 Ex: http://example.com
 Ex: https://example.com
 Ex: www.example.com
 Ex: http://www.example.com
 Ex: https://www.example.com
 Ex: https://github.com/darkmatter-index
 Ex: http://github.com/darkmatter-index
 Ex: https://www.github.com/darkmatter-index
 Ex: http://www.github.com/darkmatter-index

[ IP ]

 Ex: 192.168.0.1
 Ex: 192.168.0.0/24

[ File ]

 Ex: -f ip.txt
 Ex: -f ip1.txt -f ip2.txt -f ip3.txt

[ Exclude ]

 Ex: -e example.com
 Ex: -e http://example.com
 Ex: -e https://example.com
 Ex: -e www.example.com
 Ex: -e http://www.example.com
 Ex: -e https://www.example.com
 Ex: -e https://github.com/darkmatter-index
 Ex: -e http://github.com/darkmatter-index
 Ex: -e https://www.github.com/darkmatter-index
 Ex: -e http://www.github.com/darkmatter-index
 Ex: -e 192.168.0.1
 Ex: -e 192.168.0.0/24

[ Exclude file ]

 Ex: -ef ip.txt
 Ex: -ef ip1.txt -ef ip2.txt -ef ip3.txt

[ Port ]

Ex: 80
Ex: 21,22,80,443
Ex: 0-1024
Ex: 22,80,100-1024
Ex: 0-100,443,1024
Ex: 0-65535 (leave empty to do this)
Ex: empty (To scan all ports 0-65535)

[ Flags ]

 Syntax: <option> <value>

 Ex: -v
 Ex: -i 5
 Ex: -i 2.5
 Ex: -t 5 (normal, tor, nmap)
 Ex: -t 2.5 (normal, tor)
 Ex: -r
 Ex: -b
 Ex: -o
 Ex: -o Scan_result
 Ex: -oa
 Ex: -oa Scan_result
 Ex: -m
 Ex: -n
 Ex: empty
 
 By default,
  - Verbose = 0
  - Interval = 0
  - Timeout (normal) = 3
  - Tor = 0
  - Timeout (tor) = 5
  - Banner = 0
  - Output = 0
  - Output File = "Result.txt"
  - Append Output = 0
  - Append Output File = "Result.txt"
  - Max Active Thread (normal, nmap) = 10000
  - Max Active Thread (tor) = 5000
  - Nmap = 0
  - Timing Template (nmap) = 4
  
```

## Flags

- `-v` - Verbose. It will show you every closed or filtered (If you're using Nmap scan) port in the output.
- `-i <value>` - Interval between each scan. It is necessary to use this option while scanning multiple targets for multiple ports; otherwise, it will not give you open ports for some IP/Domain.
- `-n` - Nmap scan (SYN+ACK or stealth)
- `-r` - Use tor to hide your IP. You can't use Nmap scan while using tor.
- `-t <value>` - Wait for a maximum timeout for server response. It will automatically take a timeout in normal (3 sec), tor (5 sec), and Nmap (T4) scan. For the Nmap scan, you can specify a value between 0 and 5 to set the timing template.
- `-b` - Banner. (Useful when you're looking for vulnerability)
- `-o <value>` - Output. If the file path or name is not given for output, it will automatically create a file called "Result.txt" in the current directory.
- `-oa <value>` - Append Output. If the file path or name is not given for output, it will automatically create a file called "Result.txt" in the current directory. And if the "Result.txt" file already exists, it will append the output instead of overwriting it.
- `-m <value>` - Maximum Active Threads. Very important option because it can crash your machine or it can improve your scan performance. Check out more about what goal I set for the minimum requirement in the next section.

## Goal

- **OS:** Only Linux (Kali)
- **RAM:** 4 GB (Definitely, it will work for less than one Gb ram)
- **Processor:** i9 9th gen
- **Ports:** All (0-65535)
- **Scan Time:** Maximum 1 min (For only a single target, and the scan will completely depend on what options and values you're selecting)
- **Scan Types:** Default, tor and nmap
- **Storage:** 50 Gb (If it is important for you)

## Tor

First of all, PikachuScan is not using tor. It will transfer all your packets through the tor service (not the browser), which means you have to install the tor service on your machine. If you're using Kali Linux or any other Debian-based distribution, use `sudo apt-get install tor` to install the service, and `sudo systemctl start tor.service` to start the service. After doing these steps, the tor service will start on port 9050, and IP will be localhost (127.0.0.1) by default. Now, you can use `-r` option to start a scan with the tor.service.

Please don't scan open ports on the .onion site because it's too risky and not fully guaranteed (your real identity can leak in some scenarios). Still, if you're curious and want to scan open ports on .onion domains, increase the timeout by `-t` option because generally, you will don't get the response within 5 seconds (default value). The scan will be very slow most of the time, and it can't give accurate results, so don't depend on it. Again I'm not responsible for anything.

## Ending Point

I created this tool when I finished my core and advanced python to learn something about socket programming. I know this is not a huge achievement, but I feel it is a small reward for what I have learned. You can contribute or give me any suggestions to improve this code. Bye, have a good day. ⚡
