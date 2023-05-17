# Client-Server sniffer
This program is used to sniff incoming ip addresses(by parsing recieved packet headers).
This program should be builded as a daemon.
It was created as task for my work assignment.

## Overview
This program has some limitations, that i did not implemented. Im gonna list them bellow:

* Output of sniffed addresses to the client are limited to the ```NET_SERVER_MESSAGE_MAXLEN```
size(2048 bytes), but they can still can be accessed from ```/var/lib/work-task/[iface]``` folder.

This program declares various of modules, such as:
* ```FileSystem(fs.h)``` aggregates the methods for working with filesystem.
* ```Buffer(buf.h)``` the dynamic stretchy buffer that holds ip addresses(
Merge Sort+Binary Search backend, vector->capacity*2 ammortized constant buffer grow).
* ```Command(cmd.h)``` aggregates methods for parsing the input command from
the client, and callback it with some server code.
* ```Network(net.h)``` abstracting unix sockets methods.

This program is memory save and tested using valgrind memory checker. Also
it is thread safe, but i feel dumb when i say it, because it has only one
thread with and like no mutexes.

## Output with valgrind memory cheching

Here's the output that valgrind produces when the following client code 
is executed:

Client console(runned in separate TTY):

```bash
issa@issa:~/Coding/work-test-task$ ./Client 


####### Welcome to the Daemon CLI interface #######


(daemon-ctl) $ stat 
enp3s0:
[0] 127.0.0.1		 86
[1] 13.33.243.51		 61
[2] 64.233.162.196		 40
[3] 140.82.114.26		 4
[4] 185.199.111.133		 2
[5] 192.229.133.221		 267
[6] 185.199.108.154		 4
[7] 149.154.167.41		 41
[8] 64.233.161.139		 59
[9] 142.250.150.94		 235
[10] 142.250.150.99		 270
[11] 142.251.1.157		 1
[12] 18.165.122.111		 182
[13] 209.85.233.101		 125
[14] 140.82.121.5		 14
[15] 13.33.243.122		 35
[16] 209.85.233.94		 112
[17] 140.82.112.26		 3
[18] 64.233.161.94		 13
[19] 172.67.188.196		 195
eth0:

(daemon-ctl) $ Here's the data from my previous attempts
Error: invalid command
(daemon-ctl) $ select iface enp3s0
iface enp3s0 is binded to the sniffer
(daemon-ctl) $ I am using external net card
Error: invalid command
(daemon-ctl) $ start
start sniffing packet on iface enp3s0
(daemon-ctl) $ *scrolling google images*
Error: invalid command
(daemon-ctl) $ stop
stopping sniffing packet on iface enp3s0
(daemon-ctl) $ stat
eth0:
enp3s0:
[0] 127.0.0.1		 86
[1] 18.165.122.13		 1
[2] 13.33.243.51		 61
[3] 64.233.162.196		 40
[4] 140.82.114.26		 6
[5] 185.199.111.133		 2
[6] 192.229.133.221		 267
[7] 185.199.108.154		 4
[8] 149.154.167.41		 48
[9] 64.233.161.139		 59
[10] 142.250.150.94		 235
[11] 142.250.150.99		 270
[12] 142.251.1.157		 1
[13] 18.165.122.111		 182
[14] 209.85.233.101		 125
[15] 140.82.121.5		 14
[16] 13.33.243.122		 35
[17] 209.85.233.94		 112
[18] 52.88.48.20		 1
[19] 140.82.112.26		 3
[20] 64.233.161.94		 13
[21] 172.67.188.196		 195

(daemon-ctl) $ Here it is 52.88.48.20 is the new ip
Error: invalid command
(daemon-ctl) $ show 52.88.48.20 count
IP occurences count for 52.88.48.20: 1
(daemon-ctl) $ show 13.33.243.51 count
IP occurences count for 13.33.243.51: 61
(daemon-ctl) $ ^C 

```

Server console(runninng as non-daemon, on separate TTY):
```bash
==8970== Memcheck, a memory error detector
==8970== Copyright (C) 2002-2022, and GNU GPL'd, by Julian Seward et al.
==8970== Using Valgrind-3.19.0 and LibVEX; rerun with -h for copyright info
==8970== Command: ./Daemon
==8970==
==8970==
==8970== HEAP SUMMARY:
==8970==     in use at exit: 0 bytes in 0 blocks
==8970==   total heap usage: 139 allocs, 139 frees, 113,420 bytes allocated
==8970==
==8970== All heap blocks were freed -- no leaks are possible
==8970==
==8970== For lists of detected and suppressed errors, rerun with: -s
==8970== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)

```


Server logs(from ```/var/log/syslogs```, formatted):
```bash
2023-05-17T05:17:13.324922+03:00 issa Daemon: Waiting for incoming connection
2023-05-17T05:17:14.100978+03:00 issa Daemon: Connection established!
2023-05-17T05:17:18.124906+03:00 issa Daemon: Loading ip entries cache from /var/lib/work-task/enp3s0
2023-05-17T05:17:18.147861+03:00 issa Daemon: Dumping ip data to the /var/lib/work-task/eth0
2023-05-17T05:17:18.149118+03:00 issa Daemon: Loading ip entries cache from /var/lib/work-task/eth0
2023-05-17T05:17:41.829407+03:00 issa Daemon: Requested binding (eth0 => enp3s0)
2023-05-17T05:17:41.829944+03:00 issa Daemon: Dumping eth0 information..
2023-05-17T05:17:41.830385+03:00 issa Daemon: Dumping ip data to the /var/lib/work-task/eth0
2023-05-17T05:17:41.830670+03:00 issa Daemon: Loading enp3s0 inforation...
2023-05-17T05:17:41.831148+03:00 issa Daemon: Loading ip entries cache from /var/lib/work-task/enp3s0
2023-05-17T05:17:49.126839+03:00 issa Daemon: Started sniffing on iface enp3s0
2023-05-17T05:18:03.609899+03:00 issa Daemon: Stopped sniffing on iface enp3s0
2023-05-17T05:18:10.416437+03:00 issa Daemon: Loading ip entries cache from /var/lib/work-task/eth0
2023-05-17T05:18:10.416680+03:00 issa Daemon: Dumping ip data to the /var/lib/work-task/enp3s0
2023-05-17T05:18:10.431778+03:00 issa Daemon: Loading ip entries cache from /var/lib/work-task/enp3s0
2023-05-17T05:21:46.263140+03:00 issa Daemon: Client disconected
2023-05-17T05:21:46.268945+03:00 issa Daemon: Dumping information for iface enp3s0..
2023-05-17T05:21:46.269068+03:00 issa Daemon: Dumping ip data to the /var/lib/work-task/enp3s0
```


Server cache files(from ```/var/lib/work-task```)
```bash
issa@issa:~/Coding/work-test-task$ sudo ls /var/lib/work-task/
enp3s0	eth0
issa@issa:~/Coding/work-test-task$ sudo cat /var/lib/work-task/enp3s0 
127.0.0.1 86
18.165.122.13 1
13.33.243.51 61
64.233.162.196 40
140.82.114.26 6
185.199.111.133 2
192.229.133.221 267
185.199.108.154 4
149.154.167.41 48
64.233.161.139 59
142.250.150.94 235
142.250.150.99 270
142.251.1.157 1
18.165.122.111 182
209.85.233.101 125
140.82.121.5 14
13.33.243.122 35
209.85.233.94 112
52.88.48.20 1
140.82.112.26 3
64.233.161.94 13
172.67.188.196 195
```

