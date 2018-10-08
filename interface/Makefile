
all: main

main: main.o
	gcc -std=gnu99 -Wall -Werror -pedantic-errors main.o -o main

main.o: main.c
	gcc -std=gnu99 -Wall -Werror -pedantic-errors -c main.c

clean:
	rm -f main.o main
	
	
