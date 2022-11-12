
#include "librapam.h"

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <string.h>
#include <stdint.h>

struct librapam {
  const char          *user;
  char                *pass;
  pam_handle_t  *pam_handle;
  struct pam_conv      conv;
  int               pam_ret;
};

static int
do_pam (int num_msg, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr)
{
  struct pam_response *array_resp;
  LibraPam librapam;

  array_resp = malloc (num_msg * sizeof(struct pam_response));
  librapam = (LibraPam)appdata_ptr;
  if (!librapam)
    return PAM_FAIL_DELAY;
  for (int i = 0; i < num_msg; i++) {
    array_resp[i].resp_retcode = 0;
    if (strncmp("login:", msg[i]->msg, MAXLEN) == 0) {
      uint32_t len;
      
      len = strnlen(librapam->user, MAXLEN) + 1;
      array_resp[i].resp = malloc (len);
      strncpy (array_resp[i].resp, librapam->user, len);
    } else if (strncmp ("Password: ", msg[i]->msg, MAXLEN) == 0) {
      uint32_t len;
      
      len = strnlen(librapam->pass, MAXLEN) + 1;
      array_resp[i].resp = malloc (len);
      strncpy (array_resp[i].resp, librapam->pass, len);
    }
  }
  *resp = array_resp;
  return PAM_SUCCESS;
}

LibraPam
librapam_new (const char *user, const char *pass)
{
  LibraPam librapam;
  
  librapam = malloc (sizeof(struct librapam));
  librapam->user = user;
  librapam->pass = malloc (strnlen(pass, MAXLEN));
  strncpy(librapam->pass, pass, strnlen(pass, MAXLEN));
  librapam->pam_handle = NULL;
  librapam->conv = (struct pam_conv){do_pam,(void *)(librapam)};
  librapam->pam_ret = pam_start("librapam", NULL, &librapam->conv, &librapam->pam_handle);
  if (librapam->pam_ret != PAM_SUCCESS){
    pam_end(librapam->pam_handle, librapam->pam_ret);
    free (librapam->pass);
    free (librapam);
  }
  return librapam;
}

void
librapam_destroy (LibraPam *librapam)
{
  if ((*librapam)) {
    if ((*librapam)->pam_handle)
      pam_end ((*librapam)->pam_handle, (*librapam)->pam_ret);
    if ((*librapam)->pass)
      free ((*librapam)->pass);
    (*librapam)->pass = NULL;
    free (*librapam);
    librapam = NULL;
  }
}

bool
librapam_login (LibraPam librapam)
{
  int retval;

  retval = pam_authenticate (librapam->pam_handle, 0);
  if (retval == PAM_SUCCESS) {
    retval = pam_acct_mgmt (librapam->pam_handle, 0);
    return (retval == PAM_SUCCESS);
  }
  return false;
}

bool
librapam_change_password (LibraPam librapam)
{
  int retval;

  retval = pam_acct_mgmt (librapam->pam_handle, 0);
  if (retval == PAM_SUCCESS) {
    
  }
}
