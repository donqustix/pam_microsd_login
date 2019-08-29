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

enum {
    USERNAME_SIZE_MAX = 16, HEADER_SIZE = 10, TOKEN_SIZE = 256
};

static const unsigned char header[HEADER_SIZE] = {
    49, 138, 84, 64, 58, 19, 175, 38, 170, 252
};

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
    if (urandom_fd < 0) {
        log_error("generate_token() -> open() failed: %s", strerror(errno));
        return 1;
    }
    read(urandom_fd, data, TOKEN_SIZE);
    close(urandom_fd);
    return 0;
}

int build_microsd_token_path(const char* user, char* filepath)
{
    errno = 0;
    const struct passwd* const pwd = getpwnam(user);
    if (!pwd) {
        log_error("getpwnam() failed: %s", strerror(errno));
        return 1;
    }
    snprintf(filepath, 64, "%s/microsd_token", pwd->pw_dir);
    return 0;
}

int save_token_home(const char* user, unsigned char* token)
{
    char microsd_token_path[64];
    if (build_microsd_token_path(user, microsd_token_path))
        return 1;
    const int microsd_token_fd = open(microsd_token_path, O_WRONLY | O_CREAT);
    if (microsd_token_fd < 0) {
        log_error("save_token_home() -> open() failed: %s", strerror(errno));
        return 1;
    }
    write(microsd_token_fd, token, TOKEN_SIZE);
    close(microsd_token_fd);
    return 0;
}

int save_token_microsd(unsigned char* token, const char* user)
{
    const int microsd_fd = open("/dev/mmcblk0", O_WRONLY);
    if (microsd_fd < 0) {
        log_error("save_token_microsd() -> open() failed: %s", strerror(errno));
        return 1;
    }
#ifdef TOKEN_WRITE_HEADER
    const size_t username_size = strlen(user) + 1;
    write(microsd_fd, header, HEADER_SIZE);
    write(microsd_fd, user, username_size);
    lseek(microsd_fd, USERNAME_SIZE_MAX - username_size, SEEK_CUR);
#else
    lseek(microsd_fd, HEADER_SIZE  +  USERNAME_SIZE_MAX, SEEK_SET);
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
    if (save_token_microsd(token, user))
        return 1;
    if (save_token_home(user, token))
        return 1;
    return 0;
}

#endif
