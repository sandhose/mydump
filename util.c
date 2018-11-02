#include "util.h"

int log_level = LEVEL_ERROR;
int get_log_level() { return log_level; }
void set_log_level(int l) { log_level = l; }
