#!/bin/bash
#
#

if [ "$1" == "" ]; then
	python3 -m unittest x509sak.tests
else
	python3 -m unittest "x509sak.tests.${1}"
fi
