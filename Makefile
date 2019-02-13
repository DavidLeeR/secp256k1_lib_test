CC = gcc
OBJ = neopak.o
LDIR = lib
LIBS = -L $(LDIR) -l secp256k1

neopak: $(OBJ)
	$(CC) -o neopak $(OBJ) $(LIBS)

neopak.o: neopak.c 
	$(CC) -c neopak.c

clean:
	rm *.o 

uninstall:
	rm neopak