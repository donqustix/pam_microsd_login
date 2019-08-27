#include <stdbool.h>
#include <stddef.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "pam_microsd_tools.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    const char* username = NULL;
    const int pam_code = pam_get_user(pamh, &username, NULL);
    if (pam_code != PAM_SUCCESS) {
        log_error("pam_get_user() failed: %s", pam_strerror(pamh, pam_code));
        return PAM_AUTH_ERR;
    }
    const int microsd_fd = open("/dev/mmcblk0", O_RDONLY);
    if (microsd_fd < 0) {
        log_error("open() failed: %s", strerror(errno));
        return PAM_AUTH_ERR;
    }
    const unsigned char header_cmp[] = {
        49, 138, 84, 64, 58, 19, 175, 38, 170, 252
    };
    union {
        unsigned char header    [HEADER_CODE_SIZE    ];
                 char username  [HEADER_USERNAME_SIZE];
        unsigned char data      [TOKEN_SIZE          ];
    } token_microsd;
    read(microsd_fd,       token_microsd.header,  HEADER_CODE_SIZE);
    if (memcmp(token_microsd.header, header_cmp,  HEADER_CODE_SIZE)) {
        log_error("bad header");
        goto cleanup_microsd_fd;
    }
    const int username_size = read(microsd_fd, token_microsd.username, HEADER_USERNAME_SIZE);
    if (strcmp(token_microsd.username, username)) {
        log_error("bad user");
        goto cleanup_microsd_fd;
    }
    lseek(microsd_fd, HEADER_USERNAME_SIZE - username_size, SEEK_CUR);
    read(microsd_fd, token_microsd.data, TOKEN_SIZE);
cleanup_microsd_fd: close(microsd_fd);
    errno = 0;
    const struct passwd* const pwd = getpwnam(username);
    if (!pwd) {
        log_error("getpwnam() failed: %s", strerror(errno));
        return PAM_AUTH_ERR;
    }
    char buffer[64];
    snprintf(buffer, 64, "%s/microsd_token", pwd->pw_dir);
    const int token_home_fd = open(buffer, O_RDONLY);
    if (token_home_fd < 0)
    {
        log_error("open() - microsd_token failed: %s", strerror(errno));
        return PAM_AUTH_ERR;
    }
    unsigned char token_home[TOKEN_SIZE];
    read(token_home_fd, token_home, TOKEN_SIZE);
    close(token_home_fd);
    if (memcmp(token_microsd.data, token_home, TOKEN_SIZE))
    {
        log_error("bad token");
        return PAM_AUTH_ERR;
    }
    update_token(username);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    return PAM_SUCCESS;
}
