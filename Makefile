CC = g++
OBJ = test.o
LDIR = lib
LIBS = -L $(LDIR) -l secp256k1

test: $(OBJ)
	$(CC) -Wall -g -std=c++11 -o test $(OBJ) $(LIBS)

test.o: test.cpp
	$(CC) -Wall -g -std=c++11 -c test.cpp

clean:
	rm *.o 

uninstall:
	rm test