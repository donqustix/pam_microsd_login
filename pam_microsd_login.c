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
        goto cleanup;
    }
    const int microsd_fd = open("/dev/mmcblk0", O_RDONLY);
    if (microsd_fd < 0) {
        log_error("open() failed: %s", strerror(errno));
        goto cleanup;
    }
    const unsigned char header_cmp[] = {
        49, 138, 84, 64, 58, 19, 175, 38, 170, 252
    };
    struct {
        union {
            unsigned char header    [HEADER_CODE_SIZE    ];
                     char username  [HEADER_USERNAME_SIZE];
            unsigned char data      [TOKEN_SIZE          ];
        } microsd;
        unsigned char home[TOKEN_SIZE];
    } token;
    read(microsd_fd, token.microsd.header,  HEADER_CODE_SIZE);
    if (memcmp(token.microsd.header, header_cmp,  HEADER_CODE_SIZE)) {
        log_error("bad header");
        goto cleanup_microsd_fd;
    }
    const int username_size = read(microsd_fd, token.microsd.username, HEADER_USERNAME_SIZE);
    if (strcmp(token.microsd.username, username)) {
        log_error("bad user");
        goto cleanup_microsd_fd;
    }
    lseek(microsd_fd, HEADER_USERNAME_SIZE - username_size, SEEK_CUR);
    read(microsd_fd, token.microsd.data, TOKEN_SIZE);
    errno = 0;
    const struct passwd* const pwd = getpwnam(username);
    if (!pwd) {
        log_error("getpwnam() failed: %s", strerror(errno));
        goto cleanup_microsd_fd;
    }
    char buffer[64];
    snprintf(buffer, 64, "%s/microsd_token", pwd->pw_dir);
    const int token_home_fd = open(buffer, O_RDONLY);
    if (token_home_fd < 0) {
        log_error("open() - microsd_token failed: %s", strerror(errno));
        goto cleanup_microsd_fd;
    }
    read(token_home_fd, token.home, TOKEN_SIZE);
    if (memcmp(token.microsd.data, token.home, TOKEN_SIZE)) {
        log_error("bad token");
        goto cleanup_token_home_fd;
    }
    update_token(username);
    return PAM_SUCCESS;
cleanup_token_home_fd: close(token_home_fd);
cleanup_microsd_fd:    close(microsd_fd);
cleanup:
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    return PAM_SUCCESS;
}
