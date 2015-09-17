SHA3_TEST_C_FLAGS=-c -std=c99 -O2 -Wall -Wextra -Waggregate-return -Wcast-align -Wcast-qual -Wconversion -Wformat=2 -Winline -Wmissing-prototypes -Wmissing-declarations -Wnested-externs -Wno-import -Wpointer-arith -Wredundant-decls -Wreturn-type -Wshadow -Wstrict-prototypes -Wswitch -Wwrite-strings
SHA3_TEST_OBJS=common.o sha3.o sha3_test.o

sha3_test: ${SHA3_TEST_OBJS}
	gcc -o sha3_test ${SHA3_TEST_OBJS}

common.o: ../common.c ../common.h sha3_test.make
	gcc ${SHA3_TEST_C_FLAGS} -o common.o ../common.c

sha3.o: ../sha3.c ../common.h ../global.h ../sha3.h sha3_test.make
	gcc ${SHA3_TEST_C_FLAGS} -o sha3.o ../sha3.c

sha3_test.o: ../sha3_test.c ../sha3.h sha3_test.make
	gcc ${SHA3_TEST_C_FLAGS} -o sha3_test.o ../sha3_test.c
