#!/bin/bash

ld -x --shared -o /lib/x86_64-linux-gnu/security/pam_microsd_login.so pam_microsd_login.o
