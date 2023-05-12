CC=gcc
CCFLAGS=-Wall -Wextra
CCFLAGS_DBG=-Wall -Wextra -g -ggdb

OBJ_DAEMON=daemon/main.c daemon/net.c daemon/cmd.c
OUT_DAEMON=Daemon

OBJ_CLIENT=client/main.c 
OUT_CLIENT=Client

OBJ_TESTS=daemon/tests/test.c daemon/buf.c
OUT_TESTS=Test

daemon: 
	$(CC) -o $(OUT_DAEMON) $(CCFLAGS) $(OBJ_DAEMON) 

daemon-debug:
	$(CC) -o $(OUT_DAEMON) $(CCFLAGS_DBG) $(OBJ_DAEMON) 

client: 
	$(CC) -o $(OUT_CLIENT) $(CCFLAGS) $(OBJ_CLIENT) 



test: 
	$(CC) -o $(OUT_TESTS) $(CCFLAGS_DBG) $(OBJ_TESTS) 

.PHONY: daemon client
