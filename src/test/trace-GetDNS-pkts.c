#include <stdio.h>
#include <stdlib.h>
#include <libtrace.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <getdns/getdns.h>
#include <libpacketdump.h>

#define SEND_ASYNC 1
#define SEND_SYNC 0

static char*
test_class2name(uint16_t klass) {
    char* tmp;
    switch (klass) {
        case 1:   tmp = "IN";    break;
        case 3:   tmp = "CH";    break;
        case 4:   tmp = "HS";    break;
        case 254: tmp = "NONE";  break;
        case 255: tmp = "ANY";   break;
        default:  tmp = NULL;
    }
    return tmp;
}

static char*
test_type2name(uint16_t type) {
    char* tmp;
    switch (type) {
        case 1:	tmp = "A";	break;
        case 2:	tmp = "NS";	break;
        case 3:	tmp = "MD";	break;
        case 4:	tmp = "MF";	break;
        case 5:	tmp = "CNAME";	break;
        case 6:	tmp = "SOA";	break;
        case 7:	tmp = "MB";	break;
        case 8:	tmp = "MG";	break;
        case 9:	tmp = "MR";	break;
        case 10:	tmp = "NULL";	break;
        case 11:	tmp = "WKS";	break;
        case 12:	tmp = "PTR";	break;
        case 13:	tmp = "HINFO";	break;
        case 14:	tmp = "MINFO";	break;
        case 15:	tmp = "MX";	break;
        case 16:	tmp = "TXT";	break;
        case 17:	tmp = "RP";	break;
        case 18:	tmp = "AFSDB";	break;
        case 19:	tmp = "X25";	break;
        case 20:	tmp = "ISDN";	break;
        case 21:	tmp = "RT";	break;
        case 22:	tmp = "NSAP";	break;
        case 24:	tmp = "SIG";	break;
        case 25:	tmp = "KEY";	break;
        case 26:	tmp = "PX";	break;
        case 27:	tmp = "GPOS";	break;
        case 28:	tmp = "AAAA";	break;
        case 29:	tmp = "LOC";	break;
        case 30:	tmp = "NXT";	break;
        case 31:	tmp = "EID";	break;
        case 32:	tmp = "NIMLOC";	break;
        case 33:	tmp = "SRV";	break;
        case 34:	tmp = "ATMA";	break;
        case 35:	tmp = "NAPTR";	break;
        case 36:	tmp = "KX";	break;
        case 37:	tmp = "CERT";	break;
        case 38:	tmp = "A6";	break;
        case 39:	tmp = "DNAME";	break;
        case 40:	tmp = "SINK";	break;
        case 41:	tmp = "OPT";	break;
        case 42:	tmp = "APL";	break;
        case 43:	tmp = "DS";	break;
        case 44:	tmp = "SSHFP";	break;
        case 45:	tmp = "IPSECKEY";	break;
        case 46:	tmp = "RRSIG";	break;
        case 47:	tmp = "NSEC";	break;
        case 48:	tmp = "DNSKEY";	break;
        case 49:	tmp = "DHCID";	break;
        case 50:	tmp = "NSEC3";	break;
        case 51:	tmp = "NSEC3PARAM";	break;
        case 52:	tmp = "TLSA";	break;
        case 55:	tmp = "HIP";	break;
        case 56:	tmp = "NINFO";	break;
        case 57:	tmp = "RKEY";	break;
        case 58:	tmp = "TALINK";	break;
        case 59:	tmp = "CDS";	break;
        case 99:	tmp = "SPF";	break;
        case 100:	tmp = "UINFO";	break;
        case 101:	tmp = "UID";	break;
        case 102:	tmp = "GID";	break;
        case 103:	tmp = "UNSPEC";	break;
        case 104:	tmp = "NID";	break;
        case 105:	tmp = "L32";	break;
        case 106:	tmp = "L64";	break;
        case 107:	tmp = "LP";	break;
        case 108:	tmp = "EUI48";	break;
        case 109:	tmp = "EUI64";	break;
        case 249:	tmp = "TKEY";	break;
        case 250:	tmp = "TSIG";	break;
        case 251:	tmp = "IXFR";	break;
        case 252:	tmp = "AXFR";	break;
        case 253:	tmp = "MAILB";	break;
        case 254:	tmp = "MAILA";	break;
        case 255:	tmp = "ANY";	break;
        case 256:	tmp = "URI";	break;
        case 257:	tmp = "CAA";	break;
        case 32768:	tmp = "TA";	break;
        case 32769:	tmp = "DLV";	break;
        default: tmp = NULL;
    }
    return tmp;
}

static getdns_context* 
test_create_dns_context(getdns_transport_t transport, getdns_resolution_t mode, bool async) {
    getdns_return_t status = GETDNS_RETURN_GOOD;
    fprintf(stdout, "Creating ctx.\n");
    
    /* Create the DNS context */
    getdns_context *dns_ctx = NULL;
    status = getdns_context_create(&dns_ctx, 1);
    if (status != GETDNS_RETURN_GOOD) {
            fprintf(stderr, "Trying to create the context failed: %d\n", status);
            exit(GETDNS_RETURN_GENERIC_ERROR);
    }
    if ( transport ) {
        status = getdns_context_set_dns_transport(dns_ctx, transport);
        if (status != GETDNS_RETURN_GOOD) {
                fprintf(stderr, "Error setting transport. Exiting.\n");
                getdns_context_destroy(dns_ctx);
                exit(GETDNS_RETURN_GENERIC_ERROR);
        }
    }
    if ( mode ) {
        status = getdns_context_set_resolution_type(dns_ctx, mode);
        if (status != GETDNS_RETURN_GOOD) {
                fprintf(stderr, "Error setting mode. Exiting.\n");
                getdns_context_destroy(dns_ctx);
                exit(GETDNS_RETURN_GENERIC_ERROR);
        }
    }
    return dns_ctx;
}

static getdns_dict* 
test_set_specify_class_extension(uint16_t qclass) {
    getdns_return_t status = GETDNS_RETURN_GOOD;
    getdns_dict * exten = NULL;
    if (qclass != GETDNS_RRCLASS_IN ) {
        exten = getdns_dict_create();
        status = getdns_dict_set_int(exten, "specify_class", qclass);
        if (status != GETDNS_RETURN_GOOD) {
                fprintf(stderr, "Trying to set an extension to specify a class other than IN failed: %d\n", status);
                getdns_dict_destroy(exten);
                exit(GETDNS_RETURN_GENERIC_ERROR);
        }
    }
    return exten;
}

static getdns_return_t
test_send_query_sync(const char * qname, uint16_t qtype, uint16_t qclass, getdns_dict * exten, getdns_dict ** response, getdns_context *dns_ctx) {
    getdns_return_t status = GETDNS_RETURN_GOOD;
    
    if (qclass != 1 ) exten = test_set_specify_class_extension(qclass);
    
    status = getdns_general_sync(dns_ctx, qname, qtype, exten, response);
    if (status == GETDNS_RETURN_BAD_DOMAIN_NAME) {
            fprintf(stderr, "A bad domain name was used: %s. Exiting.\n", qname);
    }
    return status;
}

static getdns_dict*
test_send_query_tcp_res_sync(const char * qname, uint16_t qtype, uint16_t qclass) {
    getdns_return_t status = GETDNS_RETURN_GOOD;
    getdns_dict * exten = NULL;
    getdns_context *dns_ctx = NULL;
    getdns_dict * response = NULL;
    
    dns_ctx = test_create_dns_context(GETDNS_TRANSPORT_TCP_ONLY, GETDNS_RESOLUTION_RECURSING, SEND_SYNC);
    status = test_send_query_sync(qname, qtype, qclass, exten, &response, dns_ctx);
    if (status != GETDNS_RETURN_GOOD) {
            fprintf(stderr, "Error sending query.\n");
    }
    free(dns_ctx);
    return response;
}      

static getdns_dict *
test_send_query_udp_res_sync(const char * qname, uint16_t qtype, uint16_t qclass) {
    getdns_return_t status = GETDNS_RETURN_GOOD;
    getdns_dict * exten = NULL;
    getdns_context *dns_ctx = NULL;
    getdns_dict * response = NULL;
    
    dns_ctx = test_create_dns_context(GETDNS_TRANSPORT_UDP_ONLY, GETDNS_RESOLUTION_RECURSING, SEND_SYNC);
    status = test_send_query_sync(qname, qtype, qclass, exten, &response, dns_ctx);
    if (status != GETDNS_RETURN_GOOD) {
            fprintf(stderr, "Error sending query.\n");
    }
    free(dns_ctx);
    return response;
}

static getdns_dict*
test_send_query_tcp_stub_sync(const char * qname, uint16_t qtype, uint16_t qclass) {
    getdns_return_t status = GETDNS_RETURN_GOOD;
    getdns_dict * exten = NULL;
    getdns_context *dns_ctx = NULL;
    getdns_dict * response = NULL;
    
    dns_ctx = test_create_dns_context(GETDNS_TRANSPORT_TCP_ONLY, GETDNS_RESOLUTION_STUB, SEND_SYNC);
    status = test_send_query_sync(qname, qtype, qclass, exten, &response, dns_ctx);
    if (status != GETDNS_RETURN_GOOD) {
            fprintf(stderr, "Error sending query.\n");

    }
    free(dns_ctx);
    return response;
}      

static getdns_dict *
test_send_query_udp_stub_sync(const char * qname, uint16_t qtype, uint16_t qclass) {
    getdns_return_t status = GETDNS_RETURN_GOOD;
    getdns_dict * exten = NULL;
    getdns_context *dns_ctx = NULL;
    getdns_dict * response = NULL;
    
    dns_ctx = test_create_dns_context(GETDNS_TRANSPORT_UDP_ONLY, GETDNS_RESOLUTION_STUB, SEND_SYNC);
    status = test_send_query_sync(qname, qtype, qclass, exten, &response, dns_ctx);
    if (status != GETDNS_RETURN_GOOD) {
            fprintf(stderr, "Error sending query.\n");
    }
    free(dns_ctx);
    return response;
}

static getdns_dict *
test_send_query_udptcp_stub_sync(const char * qname, uint16_t qtype, uint16_t qclass) {
    getdns_return_t status = GETDNS_RETURN_GOOD;
    getdns_dict * exten = NULL;
    getdns_context *dns_ctx = NULL;
    getdns_dict * response = NULL;
    
    dns_ctx = test_create_dns_context(GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP, GETDNS_RESOLUTION_STUB, SEND_SYNC);
    status = test_send_query_sync(qname, qtype, qclass, exten, &response, dns_ctx);
    if (status != GETDNS_RETURN_GOOD) {
            fprintf(stderr, "Error sending query.\n");
    }
    free(dns_ctx);
    return response;
}

static getdns_dict *
test_send_query_udptcp_res_sync(const char * qname, uint16_t qtype, uint16_t qclass) {
    getdns_return_t status = GETDNS_RETURN_GOOD;
    getdns_dict * exten = NULL;
    getdns_context *dns_ctx = NULL;
    getdns_dict * response = NULL;
    
    dns_ctx = test_create_dns_context(GETDNS_TRANSPORT_UDP_FIRST_AND_FALL_BACK_TO_TCP, GETDNS_RESOLUTION_RECURSING, SEND_SYNC);
    status = test_send_query_sync(qname, qtype, qclass, exten, &response, dns_ctx);
    if (status != GETDNS_RETURN_GOOD) {
            fprintf(stderr, "Error sending query.\n");
    }
    free(dns_ctx);
    return response;
}

static getdns_dict*
test_send_multi_query_tcp_stub_sync(getdns_context *dns_ctx, const char * qname, uint16_t qtype, uint16_t qclass) {
    getdns_return_t status = GETDNS_RETURN_GOOD;
    getdns_dict * exten = NULL;
    getdns_dict * response = NULL;
    
    status = test_send_query_sync(qname, qtype, qclass, exten, &response, dns_ctx);
    if (status != GETDNS_RETURN_GOOD) {
            fprintf(stderr, "Error sending query.\n");

    }
    return response;
}

static void
per_packet(libtrace_packet_t *packet, int count, char *filename)
{
	uint8_t proto;
	uint32_t payload_length;
	int f;
	void *transport = NULL;

	transport = trace_get_transport(packet, &proto, &payload_length);

	/* Check if there was a transport header */
	if (transport == NULL) {
		fprintf(stderr, "No transport header\n");
		return;
	}
	if ((f = open(filename, O_CREAT | O_WRONLY | O_APPEND, 0777)) == -1) {
		fprintf(stderr, "Unable to open file: %s\n", filename);
		exit (EXIT_FAILURE);
	}
	if (proto == TRACE_IPPROTO_UDP) {
		fprintf(stdout, "%i UDP packets seen\n", count+1);
	} else if (proto == TRACE_IPPROTO_TCP) {
		fprintf(stdout, "%i TCP packets seen:\n", count+1);
	}
	fflush(stdout);
	/* redirect stdout to the file */
	int current_out = dup(1);
	if(dup2(f, 1) < 0) {
        fprintf(stderr, "Couldn't redirect output\n");
        exit (EXIT_FAILURE);
    }
	trace_dump_packet(packet);
	/* reset stdout */
	if (dup2(current_out, 1) < 0) {
		fprintf(stderr, "Couldn't reset output\n");
        exit (EXIT_FAILURE);
	}
	close(f);
	return;
}

static void
libtrace_cleanup(libtrace_t *trace, libtrace_packet_t *packet) {
	if (trace) trace_destroy(trace);
	if (packet) trace_destroy_packet(packet);
}

static void
collect_pkts(libtrace_t *trace, libtrace_packet_t *packet, int expected_num_pkts, char *filename) {
	int count = 0;
	while ( ( count < expected_num_pkts ) && trace_read_packet(trace,packet)>0 ) {
		per_packet(packet, count, filename);
		count++;
	}
}

static void
local_trace_start(libtrace_t *trace, libtrace_packet_t *packet) {
	if (trace_start(trace) == -1) {
		trace_perror(trace,"Starting trace");
		libtrace_cleanup(trace, packet);
		exit (EXIT_FAILURE);
	}
}

/* 
 * While we are paused packets will be ignored
 */
static void
local_trace_pause(libtrace_t *trace, libtrace_packet_t *packet) {
	if (trace_pause(trace) == -1) {
		trace_perror(trace,"Pausing trace");
		libtrace_cleanup(trace, packet);
		exit(EXIT_FAILURE);
	}
	/* let any other packets go */
	sleep (2);
}

int main(int argc, char** argv) {
	libtrace_t *trace = NULL;
	libtrace_packet_t *packet = NULL;
	struct libtrace_filter_t *filter = trace_create_filter("port 53");     
    getdns_context *ctx;
	int count = 0;
	struct stat fileStat;
	DIR *dir;
	struct dirent *ent;
	char *dirname = "/tmp/test_getdns_transport/";
	char fullfilepath[255];
	
	/* Ensure we have four arguments after the program name */
	if (argc != 5) {
		fprintf(stderr, "Usage: %s inputURI name type class\n", argv[0]);
		fprintf(stderr, "On FreeBSD this looks something like: %s BPF:em0 name type class\n", argv[0]);
		return EXIT_FAILURE;
	}	
	const char *qname  = argv[2];
    uint16_t qtype = atoi(argv[3]);
    uint16_t qclass = atoi(argv[4]);
    
	if (stat(dirname, &fileStat) != 0) {
		if (mkdir(dirname, 0777) != 0) {
			fprintf(stdout, "Error creating test directory: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {		
		if ((dir = opendir (dirname)) != NULL) {
			/* remove all the files except those starting with a . */
			while ((ent = readdir (dir)) != NULL) {
				if (strncmp(ent->d_name,".",1) != 0 ) {
					sprintf(fullfilepath, "%s/%s", dirname, ent->d_name);
					fprintf(stdout, "Removing old file %s\n", fullfilepath);
					if (unlink(fullfilepath) != 0 ) {
						fprintf(stdout, "Error removing old file: %s: %s\n", fullfilepath, strerror(errno));
						exit(EXIT_FAILURE);
					}
				}
			}
			closedir (dir);
		} else {
			/* could not open directory */
			fprintf(stdout, "Error opening %s\n", dirname);
			exit(EXIT_FAILURE);
		}
	}
	
	fprintf(stdout, "Query:\tName:\t%s\n\tType:\t%s\n\tClass:\t%s\n", qname, test_type2name(qtype), test_class2name(qclass));
	
	packet = trace_create_packet();
	if (packet == NULL) {
		perror("Creating libtrace packet");
		libtrace_cleanup(trace, packet);
		return EXIT_FAILURE;
	}

	trace = trace_create(argv[1]);
	if (trace_is_err(trace)) {
		trace_perror(trace,"Opening trace URL");
		libtrace_cleanup(trace, packet);
		return EXIT_FAILURE;
	}
	
	trace_config(trace,TRACE_OPTION_FILTER,filter);

	/*
	 * Recursive mode. A lot of queries get sent out lets just watch for the 
	 * first 100 
	 */
    fprintf(stdout, "Sending synchronously over udp in recursive mode...\n");
	local_trace_start(trace, packet);
    (void)test_send_query_udp_res_sync(qname, qtype, qclass);
	collect_pkts(trace, packet, 100, "/tmp/test_getdns_transport/query_udp_res_sync.out");
	local_trace_pause(trace, packet);
	fprintf(stdout, "\n\n");
	
    fprintf(stdout, "Sending synchronously over tcp in recursive mode...\n");
	local_trace_start(trace, packet);
    (void)test_send_query_tcp_res_sync(qname, qtype, qclass);
    collect_pkts(trace, packet, 100, "/tmp/test_getdns_transport/query_tcp_res_sync.out");
	local_trace_pause(trace, packet);
	fprintf(stdout, "\n\n");
	
    fprintf(stdout, "Sending synchronously over udp with fallback to tcp in recursive mode...\n");
    local_trace_start(trace, packet);
	(void)test_send_query_udptcp_res_sync(qname, qtype, qclass);
	collect_pkts(trace, packet, 100, "/tmp/test_getdns_transport/query_udptcp_res_sync.out");
 	local_trace_pause(trace, packet);
	fprintf(stdout, "\n\n");
    
	/*
	 * Stub mode. For TCP there should be 10 packets
	 * for UDP there should be 2.
	 */
    fprintf(stdout, "Sending synchronously over udp in stub mode...\n");
    local_trace_start(trace, packet);
	(void)test_send_query_udp_stub_sync(qname, qtype, qclass);
    collect_pkts(trace, packet, 2, "/tmp/test_getdns_transport/query_udp_stub_sync.out");
 	local_trace_pause(trace, packet);
	fprintf(stdout, "\n\n");
    
    fprintf(stdout, "Sending synchronously over tcp in stub mode...\n");
	local_trace_start(trace, packet);
	(void)test_send_query_tcp_stub_sync(qname, qtype, qclass);
    collect_pkts(trace, packet, 10, "/tmp/test_getdns_transport/query_tcp_stub_sync.out");
 	local_trace_pause(trace, packet);
	fprintf(stdout, "\n\n");
    
    fprintf(stdout, "Sending synchronously over udp with fallback to tcp in stub mode...\n");
	local_trace_start(trace, packet);
	(void)test_send_query_udptcp_stub_sync(qname, qtype, qclass);
    collect_pkts(trace, packet, 2, "/tmp/test_getdns_transport/query_udptcp_stub_sync.out");
 	local_trace_pause(trace, packet);
	fprintf(stdout, "\n\n");

	if (trace_is_err(trace)) {
		trace_perror(trace,"Reading packets");
		libtrace_cleanup(trace, packet);
		return EXIT_FAILURE;
	}

	libtrace_cleanup(trace, packet);
	return (EXIT_SUCCESS);
}

