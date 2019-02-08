CC = g++
OBJ = test.o
LDIR = lib
LIBS = -L $(LDIR) -l secp256k1

test: $(OBJ)
	$(CC) -o test $(OBJ) $(LIBS)

test.o: test.cpp
	$(CC) -c test.cpp

clean:
	rm *.o 

uninstall:
	rm test