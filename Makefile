GCC=gcc
FLAGS=-Wall -O2 -g
LIBS=-lpthread
INCLUDES=
OBJ=http_parser.o main.o

http_heloer.o : src/http_helper.c
	${GCC} ${FLAGS} -c src/http_helper.c ${INCLUDES}

http_parser.o : src/http_parser.c
	${GCC} ${FLAGS} -c src/http_parser.c ${INCLUDES}

main.o : src/main.c
	${GCC} ${FLAGS} -c src/main.c ${INCLUDES}

all : ${OBJ}
	${GCC} ${FLAGS} ${OBJ} -o quiiSync.out ${LIBS}

clean :
	rm *.o *.out
