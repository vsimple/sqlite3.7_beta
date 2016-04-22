

#ifndef VSIMPLE_H
#define VSIMPLE_H

#include "sqlite3.h"
#include "stdio.h"
#include "stdlib.h"


#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

#define SECURITY_CONTEXT_COLUMN_NAME "vTAG"
#define SECURITY_CONTEXT_COLUMN_TYPE "hidden INT"
#define SECURITY_CONTEXT_COLUMN_DEFAULT_FUNC "DEFAULT 0"  // vsimple getcon()
#define SECURITY_CONTEXT_COLUMN_DEFAULT "DEFAULT 0"
#define SECURITY_CONTEXT_COLUMN_DEFINITION SECURITY_CONTEXT_COLUMN_NAME " " SECURITY_CONTEXT_COLUMN_TYPE " " SECURITY_CONTEXT_COLUMN_DEFAULT


int initializeSeSqliteObjects(sqlite3 *db);
int create_security_context_column(void *pUserData, void *parse, int type, void *pNew, char **zColumn);
int sqlite3SelinuxInit(sqlite3 *db);

#ifdef __cplusplus
} /* extern "C" */
#endif  /* __cplusplus */

#endif
