/*
 * Copyright (c) 2022, Amin Khozaei <amin.khozaei@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include "librapam.h"

#include <security/pam_appl.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

struct librapam {
  const char          *user;
  const char          *pass;
  const char          *new_pass;
  pam_handle_t        *pam_handle;
  struct pam_conv     conv;
};

typedef struct librapam LibraPam;

static int do_pam (int num_msg, const struct pam_message **msg, 
                   struct pam_response **resp, void *app_data);
static LibraPam librapam_new (const char *user, const char *pass);
static void librapam_destroy(LibraPam *librapam);

struct librapam_interface librapam = {
  .check_user = &librapam_check_user,
  .change_password = &librapam_change_password,
};

static int
do_pam (int num_msg, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr)
{
  struct pam_response *array_resp;
  LibraPam *librapam;

  librapam = (LibraPam *)appdata_ptr;
  if (!librapam || num_msg <= 0)
    return PAM_FAIL_DELAY;
  array_resp = calloc (num_msg, sizeof(struct pam_response));
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

int
librapam_check_user (const char *user, const char *pass)
{
  int retval;
  LibraPam librapam;

  librapam.user = user;
  librapam.pass = pass;
  librapam.pam_handle = NULL;
  librapam.conv = (struct pam_conv){do_pam,(void *)(&librapam)};
  retval = pam_start("librapam", librapam.user, &librapam.conv, &librapam.pam_handle);
  if (retval != PAM_SUCCESS){
    pam_end (librapam.pam_handle, retval);
    return LIBRA_FAILED;
  }
  retval = pam_authenticate (librapam.pam_handle, 0);
  if (retval == PAM_SUCCESS) {
    retval = pam_acct_mgmt (librapam.pam_handle, 0);
    pam_end (librapam.pam_handle, retval);
    switch (retval) {
      case PAM_SUCCESS:
        return (LIBRA_SUCCESS);
      case PAM_NEW_AUTHTOK_REQD:
        return (LIBRA_ERR_PASS_CHANGE_REQ);
      default:
        return (LIBRA_FAILED);
    }
  }
  pam_end (librapam.pam_handle, retval);
  return (LIBRA_FAILED);
}

int
librapam_change_password (const char *user, const char *current_pass, const char *new_pass)
{
  int retval;
  LibraPam librapam;

  librapam.user = user;
  librapam.pass = current_pass;
  librapam.new_pass = new_pass;
  librapam.pam_handle = NULL;
  librapam.conv = (struct pam_conv){do_pam,(void *)(&librapam)};
  retval = pam_start("librapam", librapam.user, &librapam.conv, &librapam.pam_handle);
  if (retval != PAM_SUCCESS){
    pam_end (librapam.pam_handle, retval);
    return LIBRA_FAILED;
  }
  retval = pam_authenticate (librapam.pam_handle, 0);
  if (retval != PAM_SUCCESS){
    pam_end (librapam.pam_handle, retval);
    return (LIBRA_FAILED);
  }
  retval = pam_acct_mgmt (librapam.pam_handle, 0);
  if (retval == PAM_SUCCESS || retval == PAM_NEW_AUTHTOK_REQD) {
    int flag;

    flag = 0;
    if (retval == PAM_NEW_AUTHTOK_REQD)
      flag |= PAM_CHANGE_EXPIRED_AUTHTOK;
    retval = pam_chauthtok (librapam.pam_handle, flag);
    pam_end (librapam.pam_handle, retval);
    switch (retval) {
      case PAM_SUCCESS:
        return (LIBRA_SUCCESS);
      case PAM_AUTHTOK_ERR:
        return (LIBRA_ERR_AUTHTOK_ERR);
      case PAM_AUTHTOK_RECOVERY_ERR:
        return (LIBRA_ERR_AUTHTOK_RECOVERY_ERR);
      case PAM_AUTHTOK_LOCK_BUSY:
        return (LIBRA_ERR_AUTHTOK_LOCK_BUSY);
      case PAM_AUTHTOK_DISABLE_AGING:
        return (LIBRA_ERR_AUTHTOK_DISABLE_AGING);
      case PAM_PERM_DENIED:
        return (LIBRA_ERR_PERM_DENIED);
      case PAM_TRY_AGAIN:
        return (LIBRA_ERR_TRY_AGAIN);
      case PAM_USER_UNKNOWN:
        return (LIBRA_ERR_USER_UNKNOWN);
    }
  }
  pam_end (librapam.pam_handle, retval);
  return (LIBRA_FAILED);
}
