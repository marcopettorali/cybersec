# the compiler: gcc for C program, define as g++ for C++
CC = gcc

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -g -Wall -Wformat-zero-length
#compiler variable
PROTOCOL  = -D PROTOCOL_DEBUG
VERBOSE  = -D VERBOSE_LEVEL
# typing 'make' will invoke the first target entry in the file 
# (in this case the default target entry)
# you can name this target entry anything, but "default" or "all"
# are the most commonly used names by convention
all : client server

client : client.c util.c message.c net.c crypto.c list.c game.c game_net.c
	$(CC) $(CFLAGS) -o client client.c util.c message.c net.c crypto.c list.c game.c game_net.c -lpthread -lcrypto

#if server.c and/or util.c have been modified => recompile
server : server.c util.c list.c message.c net.c pub_key_crypto.c crypto.c
	$(CC) $(CFLAGS) -o server server.c util.c list.c message.c net.c pub_key_crypto.c crypto.c -lpthread -lcrypto

protocol : client_protocol server_protocol

client_protocol : client.c util.c message.c net.c crypto.c list.c game.c game_net.c
	$(CC) $(CFLAGS) $(PROTOCOL) -o client client.c util.c message.c net.c crypto.c list.c game.c game_net.c -lpthread -lcrypto

#if server.c and/or util.c have been modified => recompile
server_protocol : server.c util.c list.c message.c net.c pub_key_crypto.c crypto.c
	$(CC) $(CFLAGS) $(PROTOCOL) -o server server.c util.c list.c message.c net.c pub_key_crypto.c crypto.c -lpthread -lcrypto


verbose : client_verbose server_verbose

client_verbose : client.c util.c message.c net.c crypto.c list.c game.c game_net.c
	$(CC) $(CFLAGS) $(PROTOCOL) $(VERBOSE) -o client client.c util.c message.c net.c crypto.c list.c game.c game_net.c -lpthread -lcrypto

#if server.c and/or util.c have been modified => recompile
server_verbose : server.c util.c list.c message.c net.c pub_key_crypto.c crypto.c
	$(CC) $(CFLAGS) $(PROTOCOL) $(VERBOSE) -o server server.c util.c list.c message.c net.c pub_key_crypto.c crypto.c -lpthread -lcrypto

# To start over from scratch, type 'make clean'.  This
# removes the executable file, as well as old .o object
# files and *~ backup files:

clean : 
	$(RM) count *.o *~ *.exe *.exe.stackdump