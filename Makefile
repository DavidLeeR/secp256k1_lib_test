CC = gcc
OBJ = test.o
LDIR = lib
LIBS = -L $(LDIR) -l secp256k1

test: $(OBJ)
	$(CC) -o test $(OBJ) $(LIBS)

test.o: test.c 
	$(CC) -c test.c

clean:
	rm *.o 

uninstall:
	rm test