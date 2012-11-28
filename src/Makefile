INC_ALL = $(INC_SVR_COMM)
LIB_ALL = $(LIB_SVR_COMM)

LIB = libhttp_parser.a

CFLAGS = -g -Wall -fno-common -march=i686
CC  = gcc

.SUFFIXES: .o .c .cpp
.PHONY: stip rebuild clean  r R

.c.o:
	$(CC) $(CFLAGS) -o $@ $(INC_ALL)  -c $<
#.o:
#	$(CC) $(CFLAGS) -o $@ $^ $(LIB_ALL)
demo: demo.c http_request.c
	$(CC) $(CFLAGS) -o $@ $^  $(LIB_ALL)

libhttp_parser.a: http_request.o 
	ar -rs $@ $^

all: $(LIB)                

rebuild: clean $(LIB)
clean: 
	rm -f $(LIB) *.o *~    
