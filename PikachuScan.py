#!/usr/bin/python3
import os
import IPy
import sys
import time
import nmap
import regex
import socket
import struct
import ctypes
import requests
import threading
from termcolor import cprint
from collections import OrderedDict

####################################################################################
#                                 CRITICAL SECTION                                 #
####################################################################################

import socks  # Windows: pip install PySocks

# OSError: too many open files
# coderwall.com/p/ptq7rw/increase-open-files-limit-and-drop-privileges-in-python
# Comment both statements if you're on windows
try:
    import resource  # Comment
    resource.setrlimit(resource.RLIMIT_NOFILE, (131072, 131072))  # Comment
    pass
except ModuleNotFoundError:
    pass

# Error: libgcc_s.so.1 must be installed for pthread_cancel to work
try:
    libgcc_s = ctypes.CDLL('libgcc_s.so.1')
except FileNotFoundError:
    pass

# Proxy (Default: tor)
socks5_ip = '127.0.0.1'
socks5_port = 9050

####################################################################################

# PikachuScan
dm_link = "https://github.com/darkmatter-index"
dm_credit = "- Created by Darkmatter"

cprint('\n', "yellow", attrs=["bold"])
cprint(r"******************************************************************************************", "yellow", attrs=["bold"])
cprint(r"*    _____    _   _                     _                _____                           *", "yellow", attrs=["bold"])
cprint(r"*   |  __ \  (_) | |                   | |              / ____|                          *", "yellow", attrs=["bold"])
cprint(r"*   | |__) |  _  | | __   __ _    ___  | |__    _   _  | (___     ___    __ _   _ __     *", "yellow", attrs=["bold"])
cprint(r"*   |  ___/  | | | |/ /  / _` |  / __| | '_ \  | | | |  \___ \   / __|  / _` | | '_ \    *", "yellow", attrs=["bold"])
cprint(r"*   | |      | | |   <  | (_| | | (__  | | | | | |_| |  ____) | | (__  | (_| | | | | |   *", "yellow", attrs=["bold"])
cprint(r"*   |_|      |_| |_|\_\  \__,_|  \___| |_| |_|  \__,_| |_____/   \___|  \__,_| |_| |_|   *", "yellow", attrs=["bold"])
cprint(r"*                                                                                        *", "yellow", attrs=["bold"])
cprint(r"******************************************************************************************", "yellow", attrs=["bold"])
cprint(r"*                                                                                        *", "yellow", attrs=["bold"])
cprint(r"*", "yellow", attrs=["bold"], end='')
cprint(f"   {dm_link}                        {dm_credit}   ", "yellow", end='')
cprint(r"*", "yellow", attrs=["bold"])
cprint(r"*                                                                                        *", "yellow", attrs=["bold"])
cprint(r"******************************************************************************************", "yellow", attrs=["bold"])
cprint('\n', "yellow", attrs=["bold"])

# Help
try:
    if sys.argv[1] in ['help', '-h', '--help']:
        cprint("[ Starting & Disclaimer ]", "blue", attrs=["bold"])
        print("\n PikachuScan is a small and powerful tool that can scan every port (0-65535) in just")
        print(" seconds. It uses threads efficiently for speed and avoids any errors while creating")
        print(" too many threads. Note that this will not perform stealth scan (like in Nmap) because")
        print(" it uses the connect method inside the socket module to properly implement the TCP")
        print(" connect (3-way handshake). But you can use the -n option to achieve this (SYN-ACK) by")
        print(" the Nmap module. Also, you can hide your IP address by using the -r option to scan")
        print(" your target with tor.\n\n")

        cprint("[ Domain ]\n", "blue", attrs=["bold"])
        print(" Ex: example.com")
        print(" Ex: http://example.com")
        print(" Ex: https://example.com")
        print(" Ex: www.example.com")
        print(" Ex: http://www.example.com")
        print(" Ex: https://www.example.com")
        print(" Ex: https://github.com/darkmatter-index")
        print(" Ex: http://github.com/darkmatter-index")
        print(" Ex: https://www.github.com/darkmatter-index")
        print(" Ex: http://www.github.com/darkmatter-index")

        print("\n")

        cprint("[ IP ]\n", "blue", attrs=["bold"])
        print(" Ex: 192.168.0.1")
        print(" Ex: 192.168.0.0/24")

        print("\n")

        cprint("[ File ]\n", "blue", attrs=["bold"])
        print(" Ex: -f ip.txt")
        print(" Ex: -f ip1.txt -f ip2.txt -f ip3.txt")

        print("\n")

        cprint("[ Exclude ]\n", "blue", attrs=["bold"])
        print(" Ex: -e example.com")
        print(" Ex: -e http://example.com")
        print(" Ex: -e https://example.com")
        print(" Ex: -e www.example.com")
        print(" Ex: -e http://www.example.com")
        print(" Ex: -e https://www.example.com")
        print(" Ex: -e https://github.com/darkmatter-index")
        print(" Ex: -e http://github.com/darkmatter-index")
        print(" Ex: -e https://www.github.com/darkmatter-index")
        print(" Ex: -e http://www.github.com/darkmatter-index")
        print(" Ex: -e 192.168.0.1")
        print(" Ex: -e 192.168.0.0/24")

        print("\n")

        cprint("[ Exclude file ]\n", "blue", attrs=["bold"])
        print(" Ex: -ef ip.txt")
        print(" Ex: -ef ip1.txt -ef ip2.txt -ef ip3.txt")

        print("\n")

        cprint("[ Port ]\n", "blue", attrs=["bold"])
        print(" Ex: 80")
        print(" Ex: 21,22,80,443")
        print(" Ex: 0-1024")
        print(" Ex: 22,80,100-1024")
        print(" Ex: 0-100,443,1024")
        print(" Ex: 0-65535 (leave empty to do this)")
        print(" Ex: empty (To scan all ports 0-65535)")

        print("\n")

        cprint("[ Flags ]\n", "blue", attrs=["bold"])
        print(" Syntax: <option> <value>\n")
        print(" Definition:")
        cprint("  -v            ", "magenta", end='')
        print("Verbose. It will show you every closed or filtered (If you're using")
        print("                Nmap scan) port in the output.")
        cprint("  -i <value>    ", "magenta", end='')
        print("Interval between each scan. It is necessary to use this option")
        print("                while scanning multiple targets for multiple ports; otherwise, it")
        print("                will not give you open ports for some IP/Domain.")
        cprint("  -n            ", "magenta", end='')
        print("Nmap scan (SYN+ACK or stealth)")
        cprint("  -r            ", "magenta", end='')
        print("Use tor to hide your IP. You can't use Nmap scan while using tor.")
        cprint("  -t <value>    ", "magenta", end='')
        print("Wait for a maximum timeout for server response. It will")
        print("                automatically take a timeout in normal (3 sec), tor (5 sec), and")
        print("                Nmap (T4) scan. For the Nmap scan, you can specify a value between")
        print("                0 and 5 to set the timing template.")
        cprint("  -b            ", "magenta", end='')
        print("Banner. (Useful when you're looking for vulnerability)")
        cprint("  -o <value>    ", "magenta", end='')
        print("Output. If the file path or name is not given for output, it will")
        print('                automatically create a file called "Result.txt" in the current')
        print("                directory.")
        cprint("  -oa <value>   ", "magenta", end='')
        print("Append Output. If the file path or name is not given for output,")
        print('                it will automatically create a file called "Result.txt" in the')
        print('                current directory. And if the "Result.txt" file already exists, it')
        print("                will append the output instead of overwriting it.")
        cprint("  -m <value>    ", "magenta", end='')
        print("Maximum Active Threads. Very important option because it can")
        print("                crash your machine or it can improve your scan performance.")

        print("\n By default:")
        print("  - Verbose = 0")
        print("  - Interval = 0")
        print("  - Timeout (normal) = 3")
        print("  - Tor = 0")
        print("  - Timeout (tor) = 5")
        print("  - Banner = 0")
        print("  - Output = 0")
        print('  - Output File = "Result.txt"')
        print("  - Append Output = 0")
        print('  - Append Output File = "Result.txt"')
        print("  - Max Active Thread (normal, nmap) = 10000")
        print("  - Max Active Thread (tor) = 5000")
        print("  - Nmap = 0")
        print("  - Timing Template (nmap) = 4\n")

        sys.exit()
except IndexError:
    pass


def define_flag(option_lst):
    # Flags
    # 0 = Verbose, 1 = Interval, 2 = Timeout
    # 3 = Tor, 4 = TorTimeout, 5 = Banner
    # 6 = Output, 7 = OutputFile, 8 = Append
    # 9 = MaxThread, 10 = NmapScan, 11 = NmapTimeout
    predefined_lst = [0, 0, 3, 0, 5, 0, 0, "Result.txt", 0, 10000, 0, 4]
    predefined_flg = ['-v', '-i', '-t', '-r', '-b', '-o', '-oa', '-m', '-n']
    index = 0
    option_lst.pop(0)

    while index < len(option_lst):
        flag = option_lst[index]

        if flag == '-v':
            predefined_lst[0] = 1
            index += 1
        if flag == '-r':
            predefined_lst[3] = 1
            index += 1
        if flag == '-b':
            predefined_lst[5] = 1
            index += 1
        if flag == '-n':
            try:
                if os.getuid() == 0:
                    predefined_lst[10] = 1
                    index += 1
                else:
                    cprint(f"[-] Requires root privileges for Nmap Scan: {flag} \n\n", "red")
                    sys.exit()
            except AttributeError:
                cprint(f"[-] You can't run Nmap Scan on windows: {flag} \n\n", "red")
                sys.exit()
        if flag == '-o' or flag == '-oa':
            if flag == '-o':
                predefined_lst[6] = 1
            else:
                predefined_lst[8] = 1

            try:
                if option_lst[index+1] in predefined_flg:
                    index += 1
                    continue
                else:
                    predefined_lst[7] = str(option_lst[index+1])
                    index += 2
            except IndexError:
                index += 1

        try:
            if flag == '-i':
                predefined_lst[1] = float(option_lst[index+1])
                index += 2
            if flag == '-t':
                if '-r' in option_lst:
                    predefined_lst[4] = float(option_lst[index+1])
                elif '-n' in option_lst:
                    value = int(option_lst[index+1])
                    if 0 <= value <= 5:
                        predefined_lst[11] = value
                    else:
                        cprint(f"[-] Timing template value must be 0-5: {flag} {option_lst[index+1]} \n\n", "red")
                        sys.exit()
                else:
                    predefined_lst[2] = float(option_lst[index+1])
                index += 2
            if flag == '-m':
                max_threads = int(option_lst[index + 1])

                if 0 <= max_threads <= 65535:
                    predefined_lst[9] = max_threads
                    index += 2
                else:
                    cprint(f"[-] Threads must be 0-65535: {flag} {option_lst[index+1]} \n\n", "red")
                    sys.exit()
        except ValueError:
            cprint(f"[-] Invalid Value: {flag} {option_lst[index+1]} \n\n", "red")
            sys.exit()

        if flag not in predefined_flg:
            cprint(f"[-] Invalid Flag: {flag}\n", "red")
            cprint(f"[*] Hint", "blue")
            cprint(f"[+] Syntax: <option> <value>", "green")
            cprint(f"[+] Value can be optional for: -v -r -b -o -oa -n", "green")
            cprint(f"[+] Space is require between option and value", "green")
            cprint(f"[+] Options that can take value: -i -t -o -oa -m", "green")
            cprint(f"[+] Get help section: help -h --help\n\n", "green")
            sys.exit()

        if predefined_lst[3] and predefined_lst[10]:
            cprint(f"[-] You can't use tor while using nmap scan \n\n", "red")
            sys.exit()

    return predefined_lst


def current_time():
    cprint("[*] Initializing", "blue")
    cprint("[+] Current time      : ", "blue", end='')
    print(time.ctime())

    return time.ctime()


include_target = []
exclude_target = []


def fetch_file(file_path):
    try:
        with open(file_path) as handler:
            lines_lst = handler.readlines()
    except FileNotFoundError:
        cprint(f"\n[-] File {file_path} not found\n", "red")
        sys.exit()

    fetch_file_lst = [rm_newline.replace('\n', '') for rm_newline in lines_lst]
    return fetch_file_lst


def separate_target(target_lst):
    global include_target, exclude_target

    length = len(target_lst)
    index = 0

    while True:
        if index < length:
            try:
                value = target_lst[index]

                if value == '-f':
                    target_lst.pop(index)
                    for target in fetch_file(target_lst.pop(index)):
                        include_target.append(target)

                elif value == '-ef':
                    target_lst.pop(index)
                    for target in fetch_file(target_lst.pop(index)):
                        exclude_target.append(target)

                elif value == '-e':
                    target_lst.pop(index)
                    rv = target_lst.pop(index)
                    exclude_target.append(rv)

                else:
                    include_target.append(value)
                    index += 1
            except IndexError:
                break
        else:
            break

    include_target = list(OrderedDict.fromkeys(include_target))
    exclude_target = list(OrderedDict.fromkeys(exclude_target))
    include_target = [target for target in include_target if target != '']
    exclude_target = [target for target in exclude_target if target != '']


def cidr_ip(target_lst, insert_index, target_ip):
    try:
        target_cidr = IPy.IP(target_ip)
        target_lst.pop(insert_index)
        count_index = 0

        for target_ip in target_cidr:
            target_ip = str(target_ip)
            target_lst.insert(insert_index + count_index, target_ip)
            count_index += 1

    except ValueError:
        pass


def add_www(target_lst, target_url, index):
    if target_url.endswith(".onion"):
        pass
    else:
        try:
            first, last = str(target_url).split('.')
            if first != '' and last != '':
                target_lst.pop(index)
                target_lst.insert(index, f"www.{first}.{last}")
        except ValueError:
            pass


def sanitize_target(target_lst):
    index = 0
    length = len(target_lst)

    while index < length:
        string = target_lst[index]

        # IP
        match = regex.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", string)
        if hasattr(match, "group") and match.group() != '' and match.group() == string:
            if '/' in match.group():
                cidr_ip(target_lst, index, match.group())
                length = len(target_lst)
            else:
                index += 1

        else:
            # URL
            match = regex.search(r"(?<=https?://)[\w]+\.+[\w.]+", string)
            if hasattr(match, "group") and match.group() != '':
                target_lst.pop(index)
                target_lst.insert(index, match.group())

            # Add www on valid URL
            else:
                match = regex.search(r"\b\w+\.\w+\b", string)
                if hasattr(match, "group") and match.group() != '' and match.group() == string:
                    add_www(target_lst, string, index)

            length = len(target_lst)
            index += 1


def define_target(target_lst):
    global include_target, exclude_target

    target_lst = target_lst.split(' ')
    separate_target(target_lst)
    sanitize_target(include_target)
    sanitize_target(exclude_target)
    include_target = list(OrderedDict.fromkeys(include_target))
    exclude_target = list(OrderedDict.fromkeys(exclude_target))
    include_target = [target for target in include_target if target not in exclude_target]

    return include_target


def rm_dash(target_port):
    no_dash_lst = []

    if target_port[0] == '':
        no_dash_lst = [value for value in range(65536)]
    else:
        try:
            for value in target_port:
                if '-' in value:
                    first_last_port = value.split('-')
                    first_port = int(first_last_port[0])
                    last_port = int(first_last_port[1])

                    if (0 <= first_port <= 65535) and (0 <= last_port <= 65535):
                        port_range = last_port - first_port

                        for count in range(port_range+1):
                            count = int(first_port + count)
                            no_dash_lst.append(count)
                    else:
                        cprint("\n[-] Port must be 0-65535\n", "red")
                        sys.exit()
                else:
                    value = int(value)

                    if 0 <= value <= 65535:
                        no_dash_lst.append(value)
                    else:
                        cprint("\n[-] Port must be 0-65535\n", "red")
                        sys.exit()
        except ValueError:
            cprint("\n[-] Port must be 0-65535\n", "red")
            sys.exit()

    return no_dash_lst


def define_port(target_port):
    target_port = target_port.split(',')
    target_port = rm_dash(target_port)
    target_port = list(set(target_port))
    target_port.sort()

    return target_port


def your_ip():
    ip = []

    # Private IP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        sock.connect(('10.255.255.255', 1))
        p_ip = sock.getsockname()[0]
    except OSError:
        p_ip = '127.0.0.1'
    finally:
        sock.close()

    cprint(f"[+] Your private IP   : ", 'blue', end='')
    print(p_ip)
    ip.append(p_ip)

    # Public IP
    get_ip_from = "https://api.ipify.org"

    proxies = {
        'http': f'socks5://{socks5_ip}:{socks5_port}',
        'https': f'socks5://{socks5_ip}:{socks5_port}'
    }

    try:
        if '-r' in sys.argv:
            try:
                response = requests.get(get_ip_from, proxies=proxies).text
            except requests.exceptions.ConnectionError:
                # If the proxy is not properly set
                cprint("\n[!] Make sure you start the tor.service\n", 'yellow')
                sys.exit()
        else:
            response = requests.get(get_ip_from).text
    except requests.exceptions.ConnectionError:
        cprint("\n[-] Connection failed\n", 'red')
        sys.exit()

    cprint(f"[+] Your public IP    : ", 'blue', end='')
    print(response)
    ip.append(response)

    return ip


def total_target():
    cprint(f"[+] Total target(s)   : ", 'blue', end='')
    print(len(ip_lst))

    return len(ip_lst)


def half_output(flg, cto, ilo, plo, yio, tto):
    if flg[6] or flg[8]:
        if flg[6]:
            handler = open(flg[7], 'w')
        else:
            handler = open(flg[7], 'a')

        handler.write("******************************************************************************************\n")
        handler.write("*                                     PikachuScan.py                                     *\n")
        handler.write("******************************************************************************************\n\n")
        handler.write(f"[*] Initializing\n")
        handler.write(f"[+] Current time      : {cto}\n")
        handler.write(f"[+] Enter target(s)   : {ilo}\n")
        handler.write(f"[+] Enter port(s)     : {plo}\n")
        handler.write(f"[+] Your private IP   : {yio[0]}\n")
        handler.write(f"[+] Your public IP    : {yio[1]}\n")
        handler.write(f"[+] Total target(s)   : {tto}\n\n")


def is_private_ip(ip):
    if ip.startswith("192.168") or ip.startswith("10") or ip.startswith("172"):
        temp_ip = ip.split('.')
        ip = []

        for value in temp_ip:
            try:
                ip.append(int(value))
            except ValueError:
                ip.append(value)

        if len(ip) <= 4:
            try:
                if ip[0] == 172 and (16 <= ip[1] <= 31) and (0 <= ip[2] <= 255) and (0 <= ip[3] <= 255):
                    return 1
                elif ip[0] == 192 and ip[1] == 168 and (0 <= ip[2] <= 255) and (0 <= ip[3] <= 255):
                    return 1
                elif ip[0] == 10 and (0 <= ip[1] <= 255) and (0 <= ip[2] <= 255) and (0 <= ip[3] <= 255):
                    return 1
                else:
                    return 2
            except (IndexError, TypeError):
                return 0
        else:
            return 0
    else:
        return 2


def working_for(domain, flags, handler):
    scan_ip = None
    answer = None
    host_ip = None

    if ('.' not in domain) or (domain[0] == '.'):
        answer = 0
    elif domain.endswith(".onion"):
        if flags[3]:
            scan_ip = domain
            answer = 1
        else:
            cprint(f"\n[!] Use -r option to scan {domain}", "yellow")
    else:
        response = is_private_ip(domain)

        if response == 1:
            scan_ip = domain
            answer = 1
        elif response == 2:
            try:
                host_ip = socket.gethostbyname(domain)

                if host_ip == domain:
                    scan_ip = host_ip
                    host_ip = socket.gethostbyaddr(domain)
                    host_ip = host_ip[0]
                    answer = 3
                else:
                    scan_ip = host_ip
                    answer = 3

            except socket.herror:
                # Private IP: 192.168.0.1
                scan_ip = domain
                answer = 1
            except socket.gaierror:
                # Invalid IP/Domain: example.example/123.456.789.012
                answer = 0
            except UnicodeError:
                # Invalid Domain: .com, .org, .onion etc.
                answer = 0
        else:
            answer = 0

    if answer == 0:
        cprint(f"\n[-] Invalid IP/Domain {domain}", "red")
    elif answer == 1:
        cprint(f"\n[*] Working for {domain}", "blue")
    elif answer == 3:
        cprint(f"\n[*] Working for {domain} ({host_ip})", "blue")

    if handler is not None:
        if answer == 0:
            handler.write(f"\n[-] Invalid IP/Domain {domain}\n")
        elif answer == 1:
            handler.write(f"\n[*] Working for {domain}\n")
        elif answer == 3:
            handler.write(f"\n[*] Working for {domain} ({host_ip})\n")

    return scan_ip


def scanner(scan_ip, scan_port, flags, handler):
    # Flags
    # 0 = Verbose, 1 = Interval, 2 = Timeout
    # 3 = Tor, 4 = TorTimeout, 5 = Banner
    # 6 = Output, 7 = OutputFile, 8 = Append
    # 9 = MaxThread, 10 = NmapScan, 11 = NmapTimeout
    answer = None
    banner = None

    try:
        if flags[10]:
            try:
                nm = nmap.PortScanner()
                if flags[5]:
                    response = nm.scan(scan_ip, str(scan_port), f"-sS -T{flags[11]} -sV")
                    banner = [response["scan"][scan_ip]["tcp"][scan_port]["version"]]
                else:
                    response = nm.scan(scan_ip, str(scan_port), f"-sS -T{flags[11]}")

                try:
                    response = response["scan"][scan_ip]["tcp"][scan_port]["state"]
                except KeyError:
                    answer = 0

                if response == "open":
                    if flags[5]:
                        if banner[0] == '' and banner[0] is not None:
                            answer = 1
                        else:
                            answer = 2
                    else:
                        answer = 1
                elif response == "filtered":
                    if flags[0]:
                        answer = 3
                else:
                    if flags[0]:
                        answer = 0
            except nmap.nmap.PortScannerError:
                # Almost all errors
                pass
        else:
            if flags[3]:
                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, socks5_ip, socks5_port, True)
                sock = socks.socksocket()
                sock.settimeout(flags[4])
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(flags[2])
            try:
                if not sock.connect_ex((scan_ip, scan_port)):
                    if not flags[5]:
                        answer = 1

                    if flags[5]:
                        try:
                            banner = sock.recv(1024)
                            banner = str(banner.decode()).splitlines()
                            if not banner:
                                # Empty Response
                                answer = 1
                            else:
                                answer = 2
                        except socket.timeout:
                            # No banner
                            answer = 1

                else:
                    if flags[0]:
                        answer = 0
            except socket.gaierror:
                # Invalid IP
                # Normal (socket)
                pass
            except OverflowError:
                # Port out of rang
                # Normal (socket)
                pass
            except struct.error:
                # Port out of rang
                # Tor (socks)
                pass
            except TypeError:
                # Port must be integer
                # Normal (socket)
                pass
            except socket.timeout:
                # Timeout reached
                # Normal (socket) & Tor (socks)
                if flags[0]:
                    answer = 0
            except socks.SOCKS5Error:
                # Invalid IP/Port
                # Port is closed
                # Tor (socks)
                if flags[0]:
                    answer = 0
                pass
            finally:
                sock.close()
    except OSError:
        # OSError: too many open files
        cprint("[-] OSError: too many threads", "red")
        sys.exit()

    if answer == 0:
        cprint(f"[-] Port {scan_port} is closed", "red")
    elif answer == 1:
        cprint(f"[+] Port {scan_port} is open", "green")
    elif answer == 2:
        cprint(f"[+] Port {scan_port} is open ({banner[0]})", "green")
    elif answer == 3:
        cprint(f"[+] Port {scan_port} is filtered", "red")

    if handler is not None:
        if answer == 0:
            handler.write(f"[-] Port {scan_port} is closed\n")
        elif answer == 1:
            handler.write(f"[+] Port {scan_port} is open\n")
        elif answer == 2:
            handler.write(f"[+] Port {scan_port} is open ({banner[0]})\n")
        elif answer == 3:
            handler.write(f"[+] Port {scan_port} is filtered\n")


def command(handler=None):
    cprint(f"\n[*] Statistics", "blue")
    cprint(f"[+] Command           : ", 'blue', end='')
    if handler is not None:
        handler.write(f"\n\n[*] Statistics\n")
        handler.write(f"[+] Command           : ")

    for count in range(len(sys.argv)):
        if count:
            print(sys.argv[count], end=' ')
            if handler is not None:
                handler.write(f" {sys.argv[count]}")
        else:
            print("PikachuScan", end=' ')
            if handler is not None:
                handler.write("PikachuScan")


def valid_target(vt, handler=None):
    cprint(f"\n[+] Valid target(s)   : ", 'blue', end='')
    print(vt)

    if handler is not None:
        handler.write(f"\n[+] Valid target(s)   : {vt}")


def calculate_time(start_time, handler=None):
    while True:
        if threading.active_count() == 1:
            end_time = time.time()
            total_time = time.gmtime(end_time - start_time)

            cprint(f"[+] Scan time         : ", 'blue', end='')
            print(f"{total_time[3]}h {total_time[4]}m {total_time[5]}s\n")

            if handler is not None:
                handler.write(f"\n[+] Scan time         : {total_time[3]}h {total_time[4]}m {total_time[5]}s\n\n")

            break
        else:
            pass


def start(domain, ports, flags):
    start_time = time.time()
    handler = None
    valid_targets = 0

    if flags[6] or flags[8]:
        handler = open(flags[7], 'a')

    for index in range(len(domain)):
        while True:
            if threading.active_count() == 1:

                time.sleep(flags[1])
                scan_ip = working_for(domain[index], flags, handler)

                if scan_ip is not None:
                    valid_targets += 1

                    for scan_port in ports:
                        thread = threading.Thread(target=scanner, args=(scan_ip, scan_port, flags, handler))

                        if flags[9]:
                            max_active_threads = flags[9]
                        else:
                            if flags[3]:
                                max_active_threads = 5000
                            else:
                                max_active_threads = 10000

                        while True:
                            if threading.active_count() <= max_active_threads:
                                try:
                                    thread.start()
                                    break
                                except RuntimeError:
                                    # time.sleep(0.3)
                                    pass
                break
            else:
                # time.sleep(0.5)
                pass

        while True:
            if threading.active_count() == 1:
                break

    while True:
        if threading.active_count() == 1:
            if handler is not None:
                command(handler)
                valid_target(valid_targets, handler)
                calculate_time(start_time, handler)
                handler.close()
            else:
                command()
                valid_target(valid_targets)
                calculate_time(start_time)
            break
        else:
            # time.sleep(0.2)
            pass


try:
    # Flags
    # 0 = Verbose, 1 = Interval, 2 = Timeout
    # 3 = Tor, 4 = TorTimeout, 5 = Banner
    # 6 = Output, 7 = OutputFile, 8 = Append
    # 9 = MaxThread, 10 = NmapScan, 11 = NmapTimeout
    flag_lst = sys.argv.copy()
    flag_lst = define_flag(flag_lst)

    # Current Time
    c_time_o = current_time()

    # Define IP/Domain
    cprint("[+] Enter target(s)   : ", 'blue', end='')
    ip_lst = input()
    ip_lst_o = ip_lst
    ip_lst = define_target(ip_lst)

    # Define Port(s)
    cprint("[+] Enter port(s)     : ", 'blue', end='')
    port_lst = input()
    port_lst_o = port_lst
    port_lst = define_port(port_lst)

    # Public IP
    your_ip_o = your_ip()

    # Total Targets
    total_target_o = total_target()

    # Output to a file
    half_output(flag_lst, c_time_o, ip_lst_o, port_lst_o, your_ip_o, total_target_o)

    # Start the port scanner
    start(ip_lst, port_lst, flag_lst)

except KeyboardInterrupt:
    cprint("\n\n[+] Good Bye\n", "yellow")
    sys.exit()
