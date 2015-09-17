SHA3_KECCAK_TEST_C_FLAGS=-c -std=c99 -O2 -Wall -Wextra -Waggregate-return -Wcast-align -Wcast-qual -Wconversion -Wformat=2 -Winline -Wmissing-prototypes -Wmissing-declarations -Wnested-externs -Wno-import -Wpointer-arith -Wredundant-decls -Wreturn-type -Wshadow -Wstrict-prototypes -Wswitch -Wwrite-strings
SHA3_KECCAK_TEST_OBJS=common.o keccak.o keccak_test.o

keccak_test: ${SHA3_KECCAK_TEST_OBJS}
	gcc -o keccak_test ${SHA3_KECCAK_TEST_OBJS}

common.o: ../common.c ../common.h keccak_test.make
	gcc ${SHA3_KECCAK_TEST_C_FLAGS} -o common.o ../common.c

keccak.o: ../keccak.c ../common.h ../global.h ../keccak.h keccak_test.make
	gcc ${SHA3_KECCAK_TEST_C_FLAGS} -o keccak.o ../keccak.c

keccak_test.o: ../keccak_test.c ../sha3.h keccak_test.make
	gcc ${SHA3_KECCAK_TEST_C_FLAGS} -o keccak_test.o ../keccak_test.c
