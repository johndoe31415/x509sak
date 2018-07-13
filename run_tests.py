#!/bin/bash
#
#

export X509SAK_VERBOSE_EXECUTION="1"
export X509SAK_PAUSE_FAILED_EXECUTION="1"
if [ "$1" == "" ]; then
	python3 -m unittest x509sak.tests
else
	python3 -m unittest "x509sak.tests.${1}"
fi
