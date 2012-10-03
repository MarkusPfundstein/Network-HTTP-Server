export LD_LIBRARY_PATH=${PWD}/mods

echo $LD_LIBRARY_PATH

VALGRIND=""

if [ ! -z $1 ]
then
    VALGRIND="valgrind --leak-check=full --show-reachable=yes"
fi

${VALGRIND} ./server.out
