#include "librapam.h"

#include <stdio.h>

int
main (int argc, char *argv[])
{
  int retval;

  retval = librapam.check_user("amin", "password_example");
  if (retval == LIBRA_SUCCESS)
    printf("login successful!\n");
  else
    printf("login failed!\n");

  retval = librapam.change_password("root", "password_example", "new_password");
  if (retval == LIBRA_SUCCESS)
    printf("the user password changed successfully\n");
  else
    printf("changing password was not successful\n");
  return 0;
}
