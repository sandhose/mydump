#include <ctype.h>

#include "util.h"

char logindent[256] = "";
static uint8_t indent_level = 0;

int log_level = LEVEL_WARN;
int get_log_level() { return log_level; }
void set_log_level(int l) { log_level = l; }

void handle_raw(const uint32_t length, const uint8_t *packet) {
  DEBUGF("Raw packet (length: %d)", length);
  PRINTF("Raw (length: %d)", length);

  if (LOG_LEVEL < LEVEL_DEBUG + 1) return;
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

void dedent_log(void) {
  indent_level -= 2;
  logindent[indent_level] = '\0';
}

void indent_log(void) {
  logindent[indent_level++] = ' ';
  logindent[indent_level++] = ' ';
  logindent[indent_level] = '\0';
}

void indent_reset(void) {
  indent_level = 0;
  logindent[0] = '\0';
}
