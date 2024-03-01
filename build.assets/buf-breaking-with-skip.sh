#!/bin/sh

if [ $# -ne 3 ] ; then
    printf "usage: %q <base input> <against input> <skip list>\n" "$0" >&2
    exit 1
fi

BUF="${BUF:-buf}"

base_input="$( "${BUF}" build "$1" --output - | sha256sum | cut -w -f1 )"
against_input="$( "${BUF}" build "$2" --output - | sha256sum | cut -w -f1 )"

if grep -q "${base_input} ${against_input}" $3 ; then
    echo "Inputs found in skip list, skipping check."
    exit 0
fi

"${BUF}" breaking "$1" --against "$2"
buf_exit=$?

if [ ${buf_exit} -eq 0 ] ; then
    exit 0
fi

if grep -q "${base_input} ${against_input}" $3 ; then
    echo "Inputs found in skip list, returning success even after a failed check."
    exit 0
fi

echo "Failed inputs:"
echo "  \"base\" input hash: ${base_input}"
echo "  \"against\" input hash: ${against_input}"

exit ${buf_exit}
