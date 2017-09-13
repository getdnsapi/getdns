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
	getdns_return_t r;

	if (!(dict = getdns_dict_create())) {
		fprintf(stderr, "Could not create dict");
		exit(EXIT_FAILURE);
	}

	r = getdns_yaml2dict(buf, &dict);
	if (r) {
		fprintf(stderr, "Error setting dict data: %s", getdns_get_errorstr_by_id(r));
		getdns_dict_destroy(dict);
		exit(EXIT_FAILURE);
	}

	char *dict_str = getdns_pretty_print_dict(dict);
	if (!dict_str) {
		fprintf(stderr, "Could not convert dict to string");
		getdns_dict_destroy(dict);
		exit(EXIT_FAILURE);
	}

	printf("%s\n", dict_str);
	free(dict_str);
	getdns_dict_destroy(dict);
	exit(EXIT_SUCCESS);
}
