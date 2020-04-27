#!/bin/sh

set -e
trap "rm -f coverage.log" EXIT

COVERAGE_MINIMUM=20
COVERAGE_PASS="true"

coverage run -m unittest discover src
coverage report -m | tee coverage.log

for FILE in $(find src/ -type f | grep -v -e "__" -e request_helper -e "/test" -e "src/[^/]*.py" | grep py$);
do
    if [ $(grep "$FILE" coverage.log | wc -l) -gt 0 ];
    then
        COVERAGE=$(grep "$FILE" coverage.log | awk '{print $4}' | sed 's/%//g')
        if [ $COVERAGE -le $COVERAGE_MINIMUM ]
        then
            echo "FAILURE: Test coverage below target ${COVERAGE_MINIMUM}% for '$FILE'"
            COVERAGE_PASS="false"
        else
            echo "SUCCESS: Test coverage at or above target ${COVERAGE_MINIMUM}% for '$FILE'"
        fi
    else
        echo "FAILURE: Unable to find test results for '$FILE'"
        COVERAGE_PASS="false"
    fi
done

if [ "$COVERAGE_PASS" != "true" ]
then
    exit -1
fi

