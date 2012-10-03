export LD_LIBRARY_PATH=${PWD}/mods

echo $LD_LIBRARY_PATH

VALGRIND=""
SUPPS="no"
SUPP_FILE="${PWD}/valgrind_server.supp"

if [ ! -z $1 ]
then
    echo "Use suppression file: ${SUPP_FILE}"
    VALGRIND="valgrind --suppressions=${SUPP_FILE} --leak-check=full --show-reachable=yes --gen-suppressions=${SUPPS}"
fi

${VALGRIND} ./server.out
