#include "librapam.h"

#include <stdio.h>

int
main (int argc, char *argv[])
{
  LibraPam librapam;

  librapam = librapam_new("amin","password");
  if (librapam_login(librapam))
    printf("login successful!\n");
  else
    printf("login failed!\n");
  librapam_destroy (&librapam);
  return 0;
}
