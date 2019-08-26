all: pam_microsd_login.c
	gcc -fPIC -fno-stack-protector -c pam_microsd_login.c -o pam_microsd_login.o
