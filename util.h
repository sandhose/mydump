#ifndef __UTIL_H
#define __UTIL_H

#include <stdio.h>
#include <stdint.h>

// Permet de définir LOG_LEVEL à une constante, à la compilation ou par
// programme. C'est le cas de dump, qui a son niveau de log au maximum, quoi
// qu'il arrive.
#ifndef LOG_LEVEL
#define LOG_LEVEL get_log_level()
#endif

// "Niveau" de chaque type de log. Au début, c'était de 0 à 4, mais le test qui
// vérifiait les niveaux de logs ne passait pas avec ça.
#define LEVEL_FATAL 0
#define COLOR_FATAL "\x1b[1;35;7m" // Magenta
#define LEVEL_ERROR 1
#define COLOR_ERROR "\x1b[1;31;7m" // Red
#define LEVEL_WARN 2
#define COLOR_WARN "\x1b[1;33;7m" // Yellow
#define LEVEL_INFO 3
#define COLOR_INFO "\x1b[1;32;7m" // Green
#define LEVEL_DEBUG 4
#define COLOR_DEBUG "\x1b[1;36;7m" // Cyan

// Macros pour logger.
// À chaque fois, une variante avec et sans formattage à la printf.
// J'ai dû séparer pour pas avoir à traîner des retours à la ligne, et quand
// même faire un seul appel à fprintf.
#define FATAL(MSG) LOG(FATAL, MSG "\n", logindent)
#define FATALF(MSG, ...) LOG(FATAL, MSG "\n", logindent, __VA_ARGS__)
#define ERROR(MSG) LOG(ERROR, MSG "\n", logindent)
#define ERRORF(MSG, ...) LOG(ERROR, MSG "\n", logindent, __VA_ARGS__)
#define WARN(MSG) LOG(WARN, MSG "\n", logindent)
#define WARNF(MSG, ...) LOG(WARN, MSG "\n", logindent, __VA_ARGS__)
#define INFO(MSG) LOG(INFO, MSG "\n", logindent)
#define INFOF(MSG, ...) LOG(INFO, MSG "\n", logindent, __VA_ARGS__)
#define DEBUG(MSG) LOG(DEBUG, MSG "\n", logindent)
#define DEBUGF(MSG, ...) LOG(DEBUG, MSG "\n", logindent, __VA_ARGS__)

// Double expansion technique to convert __LINE__ into string literal
#define S(x) #x
#define S_(x) S(x)

// Compiler avec `-DNO_COLOR` pour desactiver les couleurs.
// TODO: Utiliser isatty afficher intelligemment des couleurs.
#ifdef NO_COLOR
#define LEVEL_FMT(LEVEL) #LEVEL
#define LOC_FMT __FILE__ ":" S_(__LINE__)
#else
#define LEVEL_FMT(LEVEL) COLOR_##LEVEL " " #LEVEL " \x1b[0m"
#define LOC_FMT "\x1b[90m" __FILE__ ":" S_(__LINE__) "\x1b[0m"
#endif

// Macro interne pour formatter un message de logs (en couleur), avec
// [niveau] [fichier]:[ligne] [message]
#define LOG_FMT(LEVEL, ...) LEVEL_FMT(LEVEL) "\t" LOC_FMT "\t%s" __VA_ARGS__
#define LOG(LEVEL, ...)                                                        \
  {                                                                            \
    if (LEVEL_##LEVEL <= LOG_LEVEL) {                                          \
      fprintf(stderr, LOG_FMT(LEVEL, __VA_ARGS__));                            \
      fflush(stderr);                                                          \
    }                                                                          \
  }

#define PRINTF(...) \
  {                                                                            \
    if (LOG_LEVEL < LEVEL_DEBUG)                                               \
      printf(__VA_ARGS__);                                                     \
  }

#define APPLY_OVERHEAD_S(overhead, length, packet)                             \
  {                                                                            \
    if ((int)(length) < (int)(overhead)) {                                     \
      WARNF("Packet too small (%d < %d)", (length), (int)(overhead));          \
      return;                                                                  \
    }                                                                          \
    length -= (overhead);                                                      \
    packet += (overhead);                                                      \
  }

#define APPLY_OVERHEAD(structure, length, packet)                              \
    APPLY_OVERHEAD_S(sizeof(structure), length, packet)

extern char logindent[256];

int get_log_level();
void set_log_level(int);
void handle_raw(const uint32_t length, const uint8_t *packet);
void indent_log(void);
void dedent_log(void);
void indent_reset(void);

#endif
