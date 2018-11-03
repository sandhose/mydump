#include <ctype.h>

#include "util.h"

int log_level = LEVEL_ERROR;
int get_log_level() { return log_level; }
void set_log_level(int l) { log_level = l; }

void handle_raw(const uint32_t length, const uint8_t *packet) {
  DEBUGF("Raw packet (length: %d)", length);
  for (uint32_t i = 0; i * 16 < length; i++) {
    // Display 2 groups of 2*16 hex characters
    for (uint32_t j = 0; j < 16; j++) {
      if (j + i * 16 < length) {
        printf("%02x ", packet[i * 16 + j]);
      } else {
        printf("   ");
      }

      if (j == 7) printf(" ");
    }

    printf("  ");

    // Display the same 16 characters in ascii if they are printable
    for (uint32_t j = 0; j < 16; j++) {
      if (j + i * 16 < length) {
        if (isprint(packet[i * 16 + j])) {
          printf("%c", packet[i * 16 + j]);
        } else {
          printf(".");
        }
      } else {
        printf(" ");
      }

      if (j == 7) printf(" ");
    }
    printf("\n");
  }
  fflush(stdout);
}
