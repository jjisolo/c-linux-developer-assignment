CC=gcc
CCFLAGS=-Wall -Wextra
CCFLAGS_DBG=-Wall -Wextra -g

OBJ_DAEMON=daemon/main.c daemon/net.c daemon/cmd.c daemon/buf.c daemon/fs.c
OUT_DAEMON=wt-daemon

OBJ_CLIENT=client/main.c 
OUT_CLIENT=wt-client

PREFIX=/usr/bin/

daemon: 
	$(CC) -o $(OUT_DAEMON) $(CCFLAGS) $(OBJ_DAEMON) 

daemon-debug:
	$(CC) -o $(OUT_DAEMON) $(CCFLAGS_DBG) $(OBJ_DAEMON) 

client: 
	$(CC) -o $(OUT_CLIENT) $(CCFLAGS) $(OBJ_CLIENT) 

install:
	mv $(OUT_DAEMON) $(PREFIX) && mv $(OUT_CLIENT) $(PREFIX) 


.PHONY: daemon client
