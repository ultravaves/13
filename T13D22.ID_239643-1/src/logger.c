#include "logger.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static FILE* log_file = NULL;

void log_init(const char* filename) {
    if (log_file != NULL) {
        log_close();
    }
    log_file = fopen(filename, "a");
}

void logcat(log_level_t level, const char* message) {
    if (log_file == NULL) return;

    time_t now;
    time(&now);
    const struct tm* timeinfo = localtime(&now);  // Добавлен const
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);

    const char* level_str;
    switch (level) {
        case DEBUG:
            level_str = "DEBUG";
            break;
        case INFO:
            level_str = "INFO";
            break;
        case WARNING:
            level_str = "WARNING";
            break;
        case ERROR:
            level_str = "ERROR";
            break;
        default:
            level_str = "UNKNOWN";
    }

    fprintf(log_file, "[%s] %s - %s\n", level_str, time_str, message);
    fflush(log_file);
}

void log_close() {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}
