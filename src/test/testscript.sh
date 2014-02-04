#!/bin/sh

# run $1 > $2 and exit on failure to execute
runit () {
	echo -n "Test $1:"
	./$1 > $2
	if test $? -ne 0; then
		echo " failed (execution failed)"
		exit 1
	fi
}

# check output files $1 and $2, exit on failure
diffit () {
	if diff $1 $2; then
		echo " OK"
	else
		echo " failed (differences above)"
		exit 1
	fi
}

# check output of program $1, known_good must be in $1.good
checkoutput () {
	runit $1 output
	diffit output $1.good
}

# filter out TTL and bindata stuff from $1 to $2
filterout () {
	sed -e '/"ttl"/d' -e '/"ipv4_address"/d' -e '/"ipv6_address"/d' -e '/"rdata_raw"/d' -e '/<bindata/d' -e '/"serial"/d' <$1 >$2
}

# like checkoutput but removes addresses and TTLs and bindata
# this makes the test almost useless, but it tests runtime lookup
# and the structure of the answer format, against the live internet.
checkpacket () {
	runit $1 output
	cp $1.good output.good
	filterout output output2
	filterout output.good output2.good
	diffit output2 output2.good
}

echo "./check_getdns"
./check_getdns
if test $? -ne 0; then
	echo " failed (unit test execution failed)"
	exit 1
fi
checkoutput tests_dict
checkoutput tests_list 
checkpacket tests_stub_async 
checkpacket tests_stub_sync

rm -f output output.good output2 output2.good
exit 0
