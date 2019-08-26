#define TOKEN_WRITE_HEADER
#include "pam_microsd_tools.h"

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("init_microsd username");
        return 1;
    }
    return update_token(argv[1]);
}
