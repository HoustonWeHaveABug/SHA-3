SHA3_TEST_DEBUG_C_FLAGS=-g -c -std=c99 -Wall -Wextra -Waggregate-return -Wcast-align -Wcast-qual -Wconversion -Wformat=2 -Winline -Wmissing-prototypes -Wmissing-declarations -Wnested-externs -Wno-import -Wpointer-arith -Wredundant-decls -Wreturn-type -Wshadow -Wstrict-prototypes -Wswitch -Wwrite-strings -DSHA3_DEBUG
SHA3_TEST_DEBUG_OBJS=common.o sha3_debug.o sha3_test_debug.o

sha3_test_debug: ${SHA3_TEST_DEBUG_OBJS}
	gcc -g -o sha3_test_debug ${SHA3_TEST_DEBUG_OBJS}

common.o: ../common.c ../common.h sha3_test_debug.make
	gcc ${SHA3_TEST_DEBUG_C_FLAGS} -o common.o ../common.c

sha3_debug.o: ../sha3.c ../common.h ../global.h ../sha3.h sha3_test_debug.make
	gcc ${SHA3_TEST_DEBUG_C_FLAGS} -o sha3_debug.o ../sha3.c

sha3_test_debug.o: ../sha3_test.c ../sha3.h sha3_test_debug.make
	gcc ${SHA3_TEST_DEBUG_C_FLAGS} -o sha3_test_debug.o ../sha3_test.c
