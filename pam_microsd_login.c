#include <stdbool.h>
#include <stddef.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "pam_microsd_tools.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    const char* username = NULL;
    const int pam_code = pam_get_user(pamh, &username, NULL);
    if (pam_code != PAM_SUCCESS)
    {
        log_error("pam_get_user() failed: %s", pam_strerror(pamh, pam_code));
        return PAM_AUTH_ERR;
    }
    const int microsd_fd = open("/dev/mmcblk0", O_RDONLY);
    if (microsd_fd < 0)
    {
        log_error("open() failed: %s", strerror(errno));
        return PAM_AUTH_ERR;
    }
    const unsigned char header_cmp[] = {
        49, 138, 84, 64, 58, 19, 175, 38, 170, 252
    };
    struct
    {
        union
        {
            unsigned char header[10];
            unsigned char data[TOKEN_SIZE];
        };
        bool good;
    } token_microsd;
      token_microsd.good = false;
    read(microsd_fd, token_microsd.header, sizeof token_microsd.header);
    if (memcmp(token_microsd.header, header_cmp, 10))
        log_error("bad header");
    else
    {
        read(microsd_fd, token_microsd.data, sizeof token_microsd.data);
        token_microsd.good = true;
    }
    close(microsd_fd);
    if (token_microsd.good)
    {
        errno = 0;
        const struct passwd* const pwd = getpwnam(username);
        if (!pwd)
            log_error("getpwnam() failed: %s", strerror(errno));
        else
        {
            char buffer[64];
            snprintf(buffer, 64, "%s/microsd_token", pwd->pw_dir);
            const int token_home_fd = open(buffer, O_RDONLY);
            if (token_home_fd < 0)
                log_error("open() - microsd_token failed: %s", strerror(errno));
            else
            {
                unsigned char token_home[TOKEN_SIZE];
                read(token_home_fd, token_home, TOKEN_SIZE);
                close(token_home_fd);
                if (!memcmp(token_microsd.data, token_home, TOKEN_SIZE))
                {
                    update_token(username);
                    return PAM_SUCCESS;
                }
                log_error("bad token");
            }
        }
    }
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
    return PAM_SUCCESS;
}
