#ifndef LOGGER_H
#define LOGGER_H

typedef enum { DEBUG, INFO, WARNING, ERROR } log_level_t;

void log_init(const char* filename);
void logcat(log_level_t level, const char* message);
void log_close();

#endif
