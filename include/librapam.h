
#include <stdbool.h>

#define MAXLEN 1024

struct librapam;

typedef struct librapam *LibraPam;

LibraPam librapam_new (const char *user, const char *pass);

void librapam_destroy (LibraPam *librapam);

bool librapam_login (LibraPam librapam);
bool librapam_change_password (LibraPam librapam);
