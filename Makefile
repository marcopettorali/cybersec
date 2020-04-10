# the compiler: gcc for C program, define as g++ for C++
CC = gcc

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -g -Wall


# typing 'make' will invoke the first target entry in the file 
# (in this case the default target entry)
# you can name this target entry anything, but "default" or "all"
# are the most commonly used names by convention
all : client server

client : client.c util.c
	$(CC) $(CFLAGS) -o client client.c util.c -lpthread

#if server.c and/or util.c have been modified => recompile
server : server.c util.c
	$(CC) $(CFLAGS) -o server server.c util.c -lpthread

# To start over from scratch, type 'make clean'.  This
# removes the executable file, as well as old .o object
# files and *~ backup files:

clean : 
	$(RM) count *.o *~ *.exe