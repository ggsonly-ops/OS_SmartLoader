all:
	gcc -m32 -no-pie -nostdlib -o fib fib.c
	gcc -m32 -no-pie -nostdlib -o sum sum.c
	gcc -m32 -o loader_1 loader_1.c

clean:
	-@rm -f fib sum loader_1 
