# Client-Server sniffer
This program is used to sniff incoming ip addresses(by parsing recieved packet headers).
It was created as task for my work assignment.

## Overview
This program has some limitations, that i did not implemented. Im gonna list them bellow:

* Output of sniffed addresses to the client are limited to the ```NET_SERVER_MESSAGE_MAXLEN```
size(2048 bytes), but they can still can be accessed from ```/var/lib/work-task/[iface]``` folder.

This program declares various of modules, such as:
* FileSystem(fs.h) aggregates the methods for working with filesystem.
* Buffer(buf.h) the dynamic stretchy buffer that holds ip addresses(
merge sort->binary search backend, vector->cap*2 ammortized constant
buffer grow).
* Command(cmd.h) aggregates methods for parsing the input command from
the client, and callback it with some server code.
* Network(net.h) abstracting unix sockets methods.

This program is memory save and tested using valgrind memory checher. 

## Output with valgrind memory cheching

Here's the output that valgrind produces when the following client code 
is executed:


Client console:

```bash


```


Server console(runninng as non-daemon):
```bash


```


Server logs(from /var/log/syslogs):
```bash


```


Server cache files(from /var/lib/work-task)
```bash


```

