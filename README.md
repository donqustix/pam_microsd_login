# pam_microsd_login

Linux authentication with a SD card.

## Install

```
make
sudo cp pam_microsd_login.so /lib/x86_64-linux-gnu/security/
```

Insert an SD card and run `sudo pam_init_microsd`. As a result, `microsd_token` will be created in the home directory. Change the ACL permissions of the file with `setfacl u:username:rw ~/microsd_token`.
