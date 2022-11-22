# librapam
A simple library to use Linux-pam for user login and change password. If you want to change the password using the library, you should run your program as root at this phase of the project.

For using the library, you should copy the `librapam` config file, that exists in `etc/pam.d/librapam`, into your system at `/etc/pam.d/librapam`. 
Don't change the file name, because the file name is hardcoded in the library.

# build
First of all, please clone the project.
```
git clone https://github.com/khozaei/librapam
```
Then run these sequences of commands to build the project. You need libpam and cmake to build.
```
cd librapam
mkdir build
cd build
cmake ..
make
```
## usage example
The library is so simple:
```C
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
```
## License
This library is released under Apache 2.0 open-source license.
