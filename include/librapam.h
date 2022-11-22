/*
 * Copyright (c) 2022, Amin Khozaei <amin.khozaei@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include <stdbool.h>

#define MAXLEN 1024

struct librapam;

typedef struct librapam *LibraPam;

LibraPam librapam_new (const char *user, const char *pass);

void librapam_destroy (LibraPam *librapam);

bool librapam_login (LibraPam librapam);
bool librapam_change_password (LibraPam librapam, const char *newpass);
