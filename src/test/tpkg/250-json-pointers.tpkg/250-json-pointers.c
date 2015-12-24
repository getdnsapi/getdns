#include <stdio.h>
#include <getdns/getdns.h>
#include <getdns/getdns_extra.h>

int main()
{
	getdns_return_t r = GETDNS_RETURN_MEMORY_ERROR;
	getdns_dict    *dict = NULL;
	unsigned char   bladiebla_str[] = "bla die bla";
	getdns_bindata  bladiebla = { sizeof(bladiebla_str), bladiebla_str };

	if (!(dict = getdns_dict_create()))
		fprintf(stderr, "Could not create dict");

	else if ((r = getdns_dict_set_int(dict, "/bla/bloe/blie", 53280))
	     ||  (r = getdns_dict_set_int(dict, "/bla/hola", 53281))
	     ||  (r = getdns_dict_set_int(dict, "/bla/cola/-", 1))
	     ||  (r = getdns_dict_set_int(dict, "/bla/cola/-", 2))
	     ||  (r = getdns_dict_set_int(dict, "/bla/cola/-/drie", 3))
	     ||  (r = getdns_dict_set_int(dict, "/bla/cola/-", 4))
	     ||  (r = getdns_dict_set_int(dict, "/bla/cola/1", 5))
	     ||  (r = getdns_dict_set_int(dict, "/bla/cola/2/zes", 6))
	     ||  (r = getdns_dict_set_bindata(dict, "/die/bla", &bladiebla))
	     )
		fprintf(stderr, "Error setting dict data");
	else {
		char *dict_str = getdns_pretty_print_dict(dict);

		if (!dict_str) {
			fprintf(stderr, "Could not convert dict to string");
			r = GETDNS_RETURN_MEMORY_ERROR;
		} else {
			printf("%s\n", dict_str);
			free(dict_str);
		}
	}
	if (r)
		fprintf(stderr, ": %s\n", getdns_get_errorstr_by_id(r));

	if (dict)
		getdns_dict_destroy(dict);

	if (r)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
