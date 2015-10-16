#!/usr/bin/env bash

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
SERVER_IP="8.8.8.8"
TLS_SERVER_IP="185.49.141.38~www.dnssec-name-and-shame.com"
GOOD_RESULT_SYNC="Status was: At least one response was returned"
GOOD_RESULT_ASYNC="successfull"
BAD_RESULT_SYNC="1 'Generic error'"
BAD_RESULT_ASYNC="callback_type of 703"
GOOD_COUNT=0
FAIL_COUNT=0

check_good () {
	result=`echo $1 | grep "Response code was: GOOD." | tail -1 | sed 's/ All done.'// | sed 's/Response code was: GOOD. '//`
	async_success=`echo $result | grep -c "$GOOD_RESULT_ASYNC"`
	if [[ $result =~ $GOOD_RESULT_SYNC ]] || [[ $async_success =~ 1 ]]; then
			(( GOOD_COUNT++ ))
			echo -n "PASS: "
		else
			(( FAIL_COUNT++ ))
			echo "FAIL (RESULT): " $1
			echo -n "FAIL: "
	fi
}

check_bad () {
	result=`echo $1 | grep "An error occurred:" | tail -1 | sed 's/ All done.'//`
	error=` echo $result | sed 's/An error occurred: //'`
	if [[ ! -z $result ]]; then
		if [[ $error =~ $BAD_RESULT_SYNC ]] || [[ $error =~ $BAD_RESULT_ASYNC ]]; then
				(( GOOD_COUNT++ ))
				echo -n "PASS:"
			else
				(( FAIL_COUNT++ ))
				echo "FAIL (RESULT): " $error
				echo -n "FAIL: "
		fi
	else
		(( FAIL_COUNT++ ))
		echo "FAIL (RESULT): " $1
		echo -n "FAIL: "
	fi
}

usage () {
	echo "This is a basic and temporary testing script for the transport list"
	echo "functionality that utilises getdns_query to perform multiple queries."
	echo "It will be replaced by an automated test harness in future, but"
	echo "it can be used to check the basic functionality for now. It is recommended that"
	echo "local or known test servers are used, but it should work with the default servers:"
	echo " - Google Open DNS for TCP and UDP only "
	echo  "- the getdnsapi.net test server Open Resolver for TLS, STARTTLS, TCP and UDP"
	echo "NOTE: By default this script assumes it is located in the same directory"
	echo "as the getdns_query binary. If it is not, then the location of the binary"
	echo "can be specified via the command line option."
	echo
	echo "usage: test_transport.sh"
	echo "         -p   path to getdns_query binary"
	echo "         -s   server configured for only TCP and UDP"
	echo "         -t   server configured for TLS, STARTTLS, TCP and UDP"
	echo "              (This must include the hostname e.g. 185.49.141.38~www.dnssec-name-and-shame.com)"
}

while getopts ":p:s:t:dh" opt; do
	case $opt in
		d ) set -x ;;
		p ) DIR=$OPTARG ;;
		s ) SERVER_IP=$OPTARG ; echo "Setting server to $OPTARG" ;;
		t ) TLS_SERVER_IP=$OPTARG ; echo "Setting TLS server to $OPTARG" ;;
		h ) usage ; exit ;;
	esac
done

TLS_SERVER_IP_NO_NAME=`echo ${TLS_SERVER_IP%~*}`
echo $TLS_SERVER_IP_NO_NAME

GOOD_QUERIES=(
"-s -A -q getdnsapi.net -l U      @${SERVER_IP}    "
"-s -A -q getdnsapi.net -l T      @${SERVER_IP}    "
"-s -A -q getdnsapi.net -l L      @${TLS_SERVER_IP_NO_NAME}"
"-s -A -q getdnsapi.net -l L -m   @${TLS_SERVER_IP}")
#"-s -A -q getdnsapi.net -l S      @${TLS_SERVER_IP_NO_NAME}")

GOOD_FALLBACK_QUERIES=(
"-s -A -q getdnsapi.net -l LT     @${SERVER_IP}"
"-s -A -q getdnsapi.net -l LT     @${SERVER_IP}"
"-s -A -q getdnsapi.net -l LT     @${TLS_SERVER_IP_NO_NAME}"
"-s -A -q getdnsapi.net -l LT -m  @${TLS_SERVER_IP_NO_NAME}"
"-s -A -q getdnsapi.net -l L      @${SERVER_IP} @${TLS_SERVER_IP_NO_NAME}"
"-s -G -q DNSKEY getdnsapi.net -l UT  @${SERVER_IP} -b 512 -D")

NOT_AVAILABLE_QUERIES=(
"-s -A -q getdnsapi.net -l L      @${SERVER_IP}    "
#"-s -A -q getdnsapi.net -l S      @${SERVER_IP}    "
"-s -A -q getdnsapi.net -l L -m   @${TLS_SERVER_IP_NO_NAME}    "
"-s -G -q DNSKEY getdnsapi.net -l U   @${SERVER_IP} -b 512 -D")

echo "Starting transport test"
echo
for (( i = 0; i < 2; i+=1 )); do
	if [[ i -eq 0 ]]; then
		echo "**SYNC Mode**"
	else
		echo
		echo "**ASYNC Mode**"
		SYNC_MODE=" -a "
	fi

	echo "*Success cases:"
	for (( j = 0; j < ${#GOOD_QUERIES[@]}; j+=1 )); do
		check_good "`$DIR/getdns_query $SYNC_MODE ${GOOD_QUERIES[${j}]} 2>/dev/null`"
		echo "getdns_query $SYNC_MODE ${GOOD_QUERIES[${j}]}"
		(( COUNT++ ))
	done
	
	echo "*Success fallback cases:"
	for (( j = 0; j < ${#GOOD_FALLBACK_QUERIES[@]}; j+=1 )); do
		check_good "`$DIR/getdns_query $SYNC_MODE ${GOOD_FALLBACK_QUERIES[${j}]} 2>/dev/null`"
		echo "getdns_query $SYNC_MODE ${GOOD_FALLBACK_QUERIES[${j}]}"
		(( COUNT++ ))
	done

	echo "*Transport not available cases:"
	for (( j = 0; j < ${#NOT_AVAILABLE_QUERIES[@]}; j+=1 )); do
		check_bad "`$DIR/getdns_query $SYNC_MODE ${NOT_AVAILABLE_QUERIES[${j}]} 2>&1`"
		echo "getdns_query $SYNC_MODE ${NOT_AVAILABLE_QUERIES[${j}]}"
		(( COUNT++ ))
	done
done

echo
echo "Finished transport test: did $COUNT queries, $GOOD_COUNT passes, $FAIL_COUNT failures"
echo