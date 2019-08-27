all: pam_microsd_login.c pam_init_microsd.c
	gcc -fPIC -fno-stack-protector -c pam_microsd_login.c -o pam_microsd_login.o
	gcc -shared -o pam_microsd_login.so pam_microsd_login.o -lpam
	gcc pam_init_microsd.c -o pam_init_microsd

clean:
	rm -f pam_microsd_login.o pam_microsd_login.so pam_init_microsd
