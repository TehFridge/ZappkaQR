CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -mconsole

objects = sha1.o shalib.o main.o qrcodegen.o

tester: $(objects)
	$(CC) -o ZappkaQR $(objects) $(LDFLAGS)

sha1.o: sha1.c sha1.h
	$(CC) $(CFLAGS) -c sha1.c

shalib.o: shalib.c shalib.h
	$(CC) $(CFLAGS) -c shalib.c

main.o: main.c 
	$(CC) $(CFLAGS) -c main.c
	
qrcodegen.o: qrcodegen.c qrcodegen.h
	$(CC) $(CFLAGS) -c qrcodegen.c

clean:
	del /f tester $(objects)  # Use `del` on Windows instead of `rm`
