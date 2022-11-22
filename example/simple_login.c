#include "librapam.h"

#include <stdio.h>

int
main (int argc, char *argv[])
{
  LibraPam librapam;

  librapam = librapam_new("amin","original_password");
  if (librapam_login(librapam)) {
    printf("login successful!\n");
    if (librapam_change_password (librapam, "new_password")) {
      printf("password changed successfuly\n");
    }
  }
  else
    printf("login failed!\n");
  librapam_destroy (&librapam);
  return 0;
}
