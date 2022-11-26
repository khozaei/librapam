/*
 * Copyright (c) 2022, Amin Khozaei <amin.khozaei@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#define MAXLEN 1024

#define LIBRA_ERR_PASS_CHANGE_REQ       -10
#define LIBRA_ERR_AUTHTOK_ERR           -11
#define LIBRA_ERR_AUTHTOK_RECOVERY_ERR  -12
#define LIBRA_ERR_AUTHTOK_LOCK_BUSY     -13
#define LIBRA_ERR_AUTHTOK_DISABLE_AGING -14
#define LIBRA_ERR_PERM_DENIED           -15
#define LIBRA_ERR_TRY_AGAIN             -16
#define LIBRA_ERR_USER_UNKNOWN          -17
#define LIBRA_ERR_ALLOC_FAILED          -9

#define LIBRA_SUCCESS 0
#define LIBRA_FAILED -1

struct librapam_interface {
  int (*check_user) (const char *user, const char *pass);
  int (*change_password) (const char *user, const char *current_pass, const char *new_pass);
};

extern struct librapam_interface librapam;
int librapam_check_user (const char *user, const char *pass);
int librapam_change_password (const char *user, const char *current_pass, const char *new_pass);
