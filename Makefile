# the compiler: gcc for C program, define as g++ for C++
CC = gcc

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -g -Wall -Wformat-zero-length
#compiler variable
DEBUG  = -D DEBUG_LEVEL
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

debug : client_debug server_debug

client_debug : client.c util.c message.c net.c crypto.c list.c game.c game_net.c
	$(CC) $(CFLAGS) $(DEBUG) -o client client.c util.c message.c net.c crypto.c list.c game.c game_net.c -lpthread -lcrypto

#if server.c and/or util.c have been modified => recompile
server_debug : server.c util.c list.c message.c net.c pub_key_crypto.c crypto.c
	$(CC) $(CFLAGS) $(DEBUG) -o server server.c util.c list.c message.c net.c pub_key_crypto.c crypto.c -lpthread -lcrypto

# To start over from scratch, type 'make clean'.  This
# removes the executable file, as well as old .o object
# files and *~ backup files:

clean : 
	$(RM) count *.o *~ *.exe