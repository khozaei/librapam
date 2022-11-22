
#include "librapam.h"

#include <security/pam_appl.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct librapam {
  const char          *user;
  char                *pass;
  char                *new_pass;
  pam_handle_t  *pam_handle;
  struct pam_conv      conv;
};

static int
do_pam (int num_msg, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr)
{
  struct pam_response *array_resp;
  LibraPam librapam;

  array_resp = calloc (num_msg, sizeof(struct pam_response));
  librapam = (LibraPam)appdata_ptr;
  if (!librapam)
    return PAM_FAIL_DELAY;
  for (int i = 0; i < num_msg; i++) {
    array_resp[i].resp_retcode = PAM_SUCCESS;
    if (strstr(msg[i]->msg, "login") != NULL) {
      array_resp[i].resp = strdup (librapam->user);
    } else if (strstr (msg[i]->msg, "Password") != NULL) {
      array_resp[i].resp = strdup (librapam->pass);
    } else if (strstr (msg[i]->msg, "Changing password") != NULL) {
      array_resp[i].resp = strdup (librapam->new_pass);
    } else if (strstr (msg[i]->msg, "Current password") != NULL) {
      array_resp[i].resp = strdup (librapam->pass);
    } else if (strstr (msg[i]->msg, "New password") != NULL) {
      array_resp[i].resp = strdup (librapam->new_pass);
    } else if (strstr (msg[i]->msg, "Retype new password") != NULL) {
      array_resp[i].resp = strdup (librapam->new_pass);
    }
  }
  *resp = array_resp;
  return PAM_SUCCESS;
}

static bool
start (LibraPam librapam)
{
  int retval;
  
  if (!librapam)
    return false;
  retval = pam_start("librapam", librapam->user, &librapam->conv, &librapam->pam_handle);
  if (retval != PAM_SUCCESS)
    pam_end (librapam->pam_handle, retval);
  return (retval == PAM_SUCCESS);
}

LibraPam
librapam_new (const char *user, const char *pass)
{
  LibraPam librapam;
  
  librapam = malloc (sizeof(struct librapam));
  librapam->user = user;
  librapam->pass = strdup (pass);
  librapam->new_pass = NULL;
  librapam->pam_handle = NULL;
  librapam->conv = (struct pam_conv){do_pam,(void *)(librapam)};
  return librapam;
}

void
librapam_destroy (LibraPam *librapam)
{
  if ((*librapam)) {
    if ((*librapam)->pass)
      free ((*librapam)->pass);
    (*librapam)->pass = NULL;
    if ((*librapam)->new_pass)
      free ((*librapam)->new_pass);
    (*librapam)->new_pass = NULL;
    free (*librapam);
    librapam = NULL;
  }
}

bool
librapam_login (LibraPam librapam)
{
  int retval;

  if (!librapam)
    return false;
  if (!start(librapam))
    return false;
  retval = pam_authenticate (librapam->pam_handle, 0);
  if (retval == PAM_SUCCESS) {
    retval = pam_acct_mgmt (librapam->pam_handle, 0);
    pam_end (librapam->pam_handle, retval);
    return (retval == PAM_SUCCESS);
  }
  return false;
}

bool
librapam_change_password (LibraPam librapam, const char *newpass)
{
  int retval;

  if (!(librapam) || !newpass)
    return false;
  if (!start(librapam))
    return false;
  retval = pam_authenticate (librapam->pam_handle, 0);
  if (retval != PAM_SUCCESS){
    pam_end (librapam->pam_handle, retval);
    return false;
  }
  retval = pam_acct_mgmt (librapam->pam_handle, 0);
  if (retval == PAM_SUCCESS || retval == PAM_NEW_AUTHTOK_REQD) {
    int flag;

    flag = 0;
    if (retval == PAM_NEW_AUTHTOK_REQD)
      flag |= PAM_CHANGE_EXPIRED_AUTHTOK;
    retval = pam_setcred(librapam->pam_handle, PAM_ESTABLISH_CRED);
    if (retval != PAM_SUCCESS) {
      pam_end(librapam->pam_handle,retval);
      fprintf(stderr, "error: %s\n", pam_strerror(librapam->pam_handle,retval));
      return false;
    }
    retval = pam_open_session(librapam->pam_handle,0);
    if (retval != PAM_SUCCESS) {
      pam_end(librapam->pam_handle,retval);
      fprintf(stderr, "error: %s\n", pam_strerror(librapam->pam_handle,retval));
      return false;
    }
    retval = pam_setcred (librapam->pam_handle, PAM_REINITIALIZE_CRED);
    if (retval != PAM_SUCCESS) {
      pam_end(librapam->pam_handle,retval);
      fprintf(stderr, "error: %s\n", pam_strerror(librapam->pam_handle,retval));
      return false;
    }
    librapam->new_pass = strdup(newpass);
    retval = pam_chauthtok (librapam->pam_handle, flag);
    if (retval == PAM_SUCCESS) {
      free (librapam->pass);
      librapam->pass = strdup (newpass);
      free (librapam->new_pass);
      librapam->new_pass = NULL;
      retval = pam_close_session(librapam->pam_handle,retval);
      pam_end (librapam->pam_handle, retval);
      return true;
    } else {
      fprintf (stderr, "error: %s\n", pam_strerror(librapam->pam_handle,retval));
      retval = pam_close_session(librapam->pam_handle,retval);
      retval = pam_setcred(librapam->pam_handle, PAM_DELETE_CRED);
      pam_end (librapam->pam_handle, retval);
    }
  }
  return false;
}
