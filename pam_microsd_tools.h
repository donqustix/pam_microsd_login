#ifndef PAM_MICROSD_TOOLS
#define PAM_MICROSD_TOOLS

#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <pwd.h>

static const int TOKEN_SIZE = 256;

void log_error(const char* format, ...)
{
    openlog("pam_microsd_login", LOG_CONS | LOG_PID, LOG_AUTH);
    va_list vargs;
    va_start(vargs, format);
    vsyslog(LOG_ERR, format, vargs);
    va_end(vargs);
    closelog();
}

int generate_token(unsigned char* data)
{
    const int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0)
    {
        log_error("generate_token() -> open() failed: %s", strerror(errno));
        return 1;
    }
    read(urandom_fd, data, TOKEN_SIZE);
    close(urandom_fd);
    return 0;
}

int save_token_home(const char* user, unsigned char* token)
{
    errno = 0;
    const struct passwd* const pwd = getpwnam(user);
    if (!pwd)
    {
        log_error("getpwnam() failed: %s", strerror(errno));
        return 1;
    }

    char filepath[64];
    snprintf(filepath, 64, "%s/microsd_token", pwd->pw_dir);

    const int microsd_token_fd = open(filepath, O_WRONLY | O_CREAT);
    if (microsd_token_fd < 0)
    {
        log_error("save_token_home() -> open() failed: %s", strerror(errno));
        return 1;
    }
    write(microsd_token_fd, token, TOKEN_SIZE);
    close(microsd_token_fd);
    return 0;
}

int save_token_microsd(unsigned char* token)
{
    const int microsd_fd = open("/dev/mmcblk0", O_WRONLY);
    if (microsd_fd < 0)
    {
        log_error("save_token_microsd() -> open() failed: %s", strerror(errno));
        return 1;
    }
#ifdef TOKEN_WRITE_HEADER
    const unsigned char header[] = {
        49, 138, 84, 64, 58, 19, 175, 38, 170, 252
    };
    write(microsd_fd, header, sizeof header);
#else
    lseek(microsd_fd, 10, SEEK_SET);
#endif
    write(microsd_fd, token, TOKEN_SIZE);
    close(microsd_fd);
    return 0;
}

int update_token(const char* user)
{
    unsigned char token[TOKEN_SIZE];
    if (generate_token(token))
        return 1;
    if (save_token_microsd(token))
        return 1;
    if (save_token_home(user, token))
        return 1;
    return 0;
}

#endif
