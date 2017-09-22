#include <stdio.h>
#include <stdlib.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

int main(int ac, char *av[])
{
	FILE *f;
	char *buf = NULL;
	size_t len;
	ssize_t bytes_read;

	f = fopen(av[1], "r");
	if (!f) {
		fprintf(stderr, "Could not open %s", av[1]);
		exit(EXIT_FAILURE);
	}

	bytes_read = getdelim(&buf, &len, '\0', f);
	fclose(f);

	if (bytes_read == -1) {
		fprintf(stderr, "Could not read %s", av[1]);
		exit(EXIT_FAILURE);
	}

	buf = realloc(buf, bytes_read + 1);
	if (!buf) {
		fprintf(stderr, "Could not grow buffer");
		exit(EXIT_FAILURE);
	}
	buf[bytes_read] = '\0';

	getdns_dict *dict = NULL;
	getdns_list *list = NULL;
	getdns_bindata *bindata = NULL;
	getdns_return_t r;

	if (!(dict = getdns_dict_create())) {
		fprintf(stderr, "Could not create dict");
		goto fail;
	}

	r = getdns_yaml2dict(buf, &dict);
	if (r) {
		fprintf(stderr, "Error setting dict data: %s", getdns_get_errorstr_by_id(r));
		goto fail;
	}

	/*
	 * Now add a list, bindata and int to the dict by hand to check
	 * the other yaml2* functions work.
	 */
	if (!(list = getdns_list_create())) {
		fprintf(stderr, "Could not create list");
		goto fail;
	}

	r = getdns_str2list("[\"One\", \"two\", \"three\"]", &list);
	if (r) {
		fprintf(stderr, "Error setting list data: %s", getdns_get_errorstr_by_id(r));
		goto fail;
	}

	r = getdns_dict_set_list(dict, "List entry", list);
	if (r) {
		fprintf(stderr, "Error adding list to dict: %s", getdns_get_errorstr_by_id(r));
		goto fail;
	}

	r = getdns_str2bindata("2001:7fd::1", &bindata);
	if (r) {
		fprintf(stderr, "Error setting bindata: %s", getdns_get_errorstr_by_id(r));
		goto fail;
	}

	r = getdns_dict_set_bindata(dict, "Bindata entry", bindata);
	if (r) {
		fprintf(stderr, "Error adding list to dict: %s", getdns_get_errorstr_by_id(r));
		goto fail;
	}

	uint32_t intval;
	r = getdns_str2int("32767", &intval);
	if (r) {
		fprintf(stderr, "Error setting int: %s", getdns_get_errorstr_by_id(r));
		goto fail;
	}
	if (intval != 32767) {
		fprintf(stderr, "Error reading int: wrong value");
		goto fail;
	}

	char *dict_str = getdns_pretty_print_dict(dict);
	if (!dict_str) {
		fprintf(stderr, "Could not convert dict to string");
		goto fail;
	}

	printf("%s\n", dict_str);
	free(dict_str);
	getdns_dict_destroy(dict);
	exit(EXIT_SUCCESS);

fail:
	if (dict)
		getdns_dict_destroy(dict);
	if (list)
		getdns_list_destroy(list);
	exit(EXIT_FAILURE);
}
