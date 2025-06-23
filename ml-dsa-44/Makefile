# This Makefile can be used with GNU Make or BSD Make

LIB=libml-dsa-44_clean.a
HEADERS=api.h ntt.h packing.h params.h poly.h polyvec.h reduce.h rounding.h sign.h symmetric.h fips202.h randombytes.h memory_cleanse.h
OBJECTS=ntt.o packing.o poly.o polyvec.o reduce.o rounding.o sign.o symmetric-shake.o fips202.o randombytes.o memory_cleanse.o

CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99 $(EXTRAFLAGS)

all: $(LIB)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJECTS)
	$(AR) -r $@ $(OBJECTS)

# Test targets
test_mldsa44: test_mldsa44.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -L. -lml-dsa-44_clean

test: test_mldsa44
	./test_mldsa44

clean:
	$(RM) $(OBJECTS)
	$(RM) $(LIB)
	$(RM) test_mldsa44

.PHONY: all test clean