#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pcap.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "aftypes.h"
#include "link.h"
#include "util.h"

enum mode {
  M_NONE,
  M_LIVE,
  M_OFFLINE
};

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t* open_capture(enum mode mode, const char *arg) {
  errbuf[0] = '\0'; // reset the error buffer
  if (arg == NULL) return NULL;
  switch (mode) {
    case M_LIVE:
      DEBUGF("Opening live device `%s'", arg);
      return pcap_open_live(arg, 9000, 1, 1000, errbuf);
    case M_OFFLINE:
      DEBUGF("Opening offline file `%s'", arg);
      return pcap_open_offline(arg, errbuf);
    default:
      return NULL;
  }
}

void got_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
  link_handler handler = (link_handler)args;
  handler(header->caplen, packet);
  indent_reset();
}

void usage (char *progname) {
  fprintf(stderr, "usage: %s <-i interface|-o file> [-f filter] [-v]\n", progname);
  exit(EXIT_FAILURE);
}

int main (int argc, char **argv) {
  enum mode mode = M_NONE;
  char *mode_arg = NULL;
  char *filter = NULL;
  char verbose = 1;

  int c;

  opterr = 0;

  while ((c = getopt (argc, argv, "i:o:f:v")) != -1)
    switch (c) {
      case 'i':
        mode = M_LIVE;
        mode_arg = optarg;
        break;
      case 'o':
        mode = M_OFFLINE;
        mode_arg = optarg;
        break;
      case 'f':
        filter = optarg;
        break;
      case 'v':
        verbose++;
        set_log_level(verbose);
        break;
      case '?':
        if (optopt == 'i' || optopt == 'o' || optopt == 'f') {
          ERRORF("Option -%c requires an argument.\n", optopt);
        } else if (isprint (optopt)) {
          ERRORF("Unknown option `-%c'.", optopt);
        } else {
          ERRORF("Unknown option character `\\x%x'.", optopt);
        }
        usage (argv[0]);
      default:
        abort ();
    }

  INFOF("Options parsed ; mode: %d, arg: %s, filter: %s", mode, mode_arg, filter);

  if (mode == M_NONE || optind >= argc)
    usage (argv[0]);

  pcap_t* capture = open_capture(mode, mode_arg);
  if (capture == NULL) {
    FATALF("%s", errbuf);
    abort();
  }

  // Check fpr libpcap warnings
  if (errbuf[0] != 0) {
    WARNF("%s", errbuf);
  }

  if (filter != NULL) {
    struct bpf_program fp;
    DEBUGF("Compiling filter `%s'", filter);
    // TODO: check for netmask
    if (pcap_compile(capture, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
      FATALF("%s", pcap_geterr(capture));
      abort();
    }

    DEBUG("Applying filter");
    if (pcap_setfilter(capture, &fp) == PCAP_ERROR) {
      FATALF("%s", pcap_geterr(capture));
      abort();
    }
  }

  uint16_t link_type = pcap_datalink(capture);
  link_handler handler = resolve_link_handler(link_type);
  if (handler == NULL) {
    ERRORF("Unsupported link type %d", link_type);
    abort();
  }

  // TODO: handle singals
  INFO("Starting loop");
  pcap_loop(capture, -1, got_packet, (void *)handler);

  DEBUG("Closing capture");
  pcap_close(capture);

  return 0;
}
