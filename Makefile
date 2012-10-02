GCC=gcc
FLAGS=-Wall -O2 -g
LIBS=-lpthread -ljson
INCLUDES=
OBJ=buffer.o http_parser.o main.o

buffer.o : src/buffer.c
	${GCC} ${FLAGS} -c src/buffer.c ${INCLUDES}

http_helper.o : src/http_helper.c
	${GCC} ${FLAGS} -c src/http_helper.c ${INCLUDES}

http_parser.o : src/http_parser.c
	${GCC} ${FLAGS} -c src/http_parser.c ${INCLUDES}

main.o : src/main.c
	${GCC} ${FLAGS} -c src/main.c ${INCLUDES}

all : ${OBJ}
	${GCC} ${FLAGS} ${OBJ} -o quiiSync.out ${LIBS}

clean :
	rm *.o *.out
