SHA3_KECCAK_TEST_DEBUG_C_FLAGS=-g -c -std=c99 -Wall -Wextra -Waggregate-return -Wcast-align -Wcast-qual -Wconversion -Wformat=2 -Winline -Wmissing-prototypes -Wmissing-declarations -Wnested-externs -Wno-import -Wpointer-arith -Wredundant-decls -Wreturn-type -Wshadow -Wstrict-prototypes -Wswitch -Wwrite-strings -DSHA3_DEBUG
SHA3_KECCAK_TEST_DEBUG_OBJS=common.o keccak_debug.o keccak_test_debug.o

keccak_test_debug: ${SHA3_KECCAK_TEST_DEBUG_OBJS}
	gcc -g -o keccak_test_debug ${SHA3_KECCAK_TEST_DEBUG_OBJS}

common.o: ../common.c ../common.h keccak_test_debug.make
	gcc ${SHA3_KECCAK_TEST_DEBUG_C_FLAGS} -o common.o ../common.c

keccak_debug.o: ../keccak.c ../common.h ../global.h ../keccak.h keccak_test_debug.make
	gcc ${SHA3_KECCAK_TEST_DEBUG_C_FLAGS} -o keccak_debug.o ../keccak.c

keccak_test_debug.o: ../keccak_test.c ../keccak.h keccak_test_debug.make
	gcc ${SHA3_KECCAK_TEST_DEBUG_C_FLAGS} -o keccak_test_debug.o ../keccak_test.c
