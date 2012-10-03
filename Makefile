GCC=gcc
FLAGS=-Wall -O2 -g
LIBS=-lpthread -ljson -lconfig -ldl
INCLUDES=
MOD_INCLUDES=-I/${PWD}/src/
#main server objects to be build
OBJ=module_map.o http_query.o json_handler.o buffer.o http_parser.o main.o

MODS=mod_html.so
#library path to mods
LD_LIBRARY_PATH=${PWD}/mods

MOD_HTML=${LD_LIBRARY_PATH}/mod_html.so

mod_html.so : ${LD_LIBRARY_PATH}/mod_html/mod_html.c
	${GCC} ${FLAGS} -fPIC -shared ${LD_LIBRARY_PATH}/mod_html/mod_html.c -o ${MOD_HTML} ${MOD_INCLUDES}

# build main server

module_map.o : src/module_map.c
	${GCC} ${FLAGS} -c src/module_map.c ${INCLUDES}

json_handler.o : src/json_handler.c
	${GCC} ${FLAGS} -c src/json_handler.c ${INCLUDES}

buffer.o : src/buffer.c
	${GCC} ${FLAGS} -c src/buffer.c ${INCLUDES}

http_query.o : src/http_query.c
	${GCC} ${FLAGS} -c src/http_query.c ${INCLUDES}

http_parser.o : src/http_parser.c
	${GCC} ${FLAGS} -c src/http_parser.c ${INCLUDES}

main.o : src/main.c
	${GCC} ${FLAGS} -c src/main.c ${INCLUDES}

all : ${OBJ} ${MODS}
	${GCC} ${FLAGS} ${OBJ} -o server.out ${LIBS}

clean :
	rm *.o *.out ${LD_LIBRARY_PATH}/*.so
