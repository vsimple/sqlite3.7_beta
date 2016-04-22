
#include "sqliteInt.h"

int initializeSeSqliteObjects(sqlite3 *db) {
    int rc = SQLITE_OK;
    char *pzErr;

#ifdef SQLITE_DEBUG
fprintf(stdout, "\n == SeSqlite Initialization == \n");
#endif


// vsimple
//**************
//    setHashMap(&hash);

    // the last 0 is to avoid copying the key inside the hash structure
    // REMEMBER TO USE MALLOC ON ALL KEYS AND NOT DEALLOCATE THEM!
//    seSQLiteHashInit(&hash, SESQLITE_HASH_STRING, 0); /* init */
//    seSQLiteHashInit(&avc, SESQLITE_HASH_INT, 0); /* init avc */
//    seSQLiteHashInit(&hash_id, SESQLITE_HASH_INT, 0); /* init mapping */
    /* register module */
//    rc = sqlite3_create_module(db, "selinuxModule", &sesqlite_mod, NULL);
//    if (rc != SQLITE_OK)
//	return rc;

#ifdef SQLITE_DEBUG
if (rc == SQLITE_OK)
    fprintf(stdout, "Module 'selinuxModule' registered successfully.\n");
else
    fprintf(stderr, "Error: unable to register 'sesqliteModule' module.\n");
#endif

// 	TODO attached databases could not have the triggers an the table, we should
//      consider adding an hook for the attach or the open database and
//	move the table and trigger creation there.
    if (rc == SQLITE_OK) {
	//rc = prepareSeSQLiteStmt(db);
#ifdef SQLITE_DEBUG
if (rc == SQLITE_OK)
    fprintf(stdout, " == SeSqlite Initialized == \n\n");
else
    fprintf(stderr, "Error: unable to create 'update_contexts_after_rename' trigger.\n");
#endif
    }

#ifdef SQLITE_DEBUG
if (rc != SQLITE_OK)
    fprintf(stderr, "Error: unable to initialize the selinux support for SQLite.\n");
#endif

    return rc;
}



int create_security_context_column(void *pUserData, void *parse, int type, void *pNew, char **zColumn) {

    sqlite3* db = pUserData;
    Parse *pParse = parse;
    Column *pCol;
    char *zName = 0;
    char *zType = 0;
    int op = 0;
    int nExtra = 0;
    Expr *pExpr;
    int c = 0;
    int i = 0;
    int iDb = 0;

    *zColumn = 0;
    *zColumn = sqlite3MPrintf(db, SECURITY_CONTEXT_COLUMN_DEFINITION);
    sqlite3Dequote(*zColumn);

    Table *p = pNew;
    iDb = sqlite3SchemaToIndex(db, p->pSchema);
#if SQLITE_MAX_COLUMN
  if( p->nCol+1>db->aLimit[SQLITE_LIMIT_COLUMN] ){
    //sqlite3ErrorMsg(pParse, "too many columns on %s", p->zName);
    return -1;
  }
#endif
    zName = sqlite3MPrintf(db, SECURITY_CONTEXT_COLUMN_NAME);
    sqlite3Dequote(zName);
    for(i=0; i<p->nCol; i++){
	if( strcmp(zName, p->aCol[i].zName) ){  // STRICMP -> strcmp vsimple421
      //sqlite3ErrorMsg(pParse, "object name reserved for internal use: %s", zName);
	    sqlite3DbFree(db, zName);
	    sqlite3DbFree(db, *zColumn);
	    return -1;
	}
    }

    if( (p->nCol & 0x7)==0 ){
	Column *aNew;
	aNew = sqlite3DbRealloc(db,p->aCol,(p->nCol+8)*sizeof(p->aCol[0]));
	if( aNew==0 ){
	    //sqlite3ErrorMsg(pParse, "memory error");
	    sqlite3DbFree(db, zName);
	    sqlite3DbFree(db, *zColumn);
	return -1;
	}
	p->aCol = aNew;
    }
    pCol = &p->aCol[p->nCol];
    memset(pCol, 0, sizeof(p->aCol[0]));
    pCol->zName = zName;

    zType = sqlite3MPrintf(db, SECURITY_CONTEXT_COLUMN_TYPE);
    sqlite3Dequote(zType);
    pCol->zType = sqlite3MPrintf(db, zType);
    pCol->affinity = SQLITE_AFF_INTEGER;
    p->nCol++;
    p->aCol[p->nCol-1].isHidden = 1;

    // vsimple419
    // vsimple420 printf("hidden column is %d, %s: %s: %s: %s\n", IsHiddenColumn(&p->aCol[p->nCol-1])?1:0, p->aCol[p->nCol-1].zName, p->aCol[p->nCol-1].zType, p->aCol[p->nCol-1].zDflt, p->aCol[p->nCol-1].pDflt);

    /**
    *generate expression for DEFAULT value
    */

    // vsimple417

    op = 151;
    nExtra = 7;
    pExpr = sqlite3DbMallocZero(db, sizeof(Expr)+nExtra);
    pExpr->op = (u8)op;
    pExpr->iAgg = -1;
    pExpr->u.zToken = (char*)&pExpr[1];
    memcpy(pExpr->u.zToken, SECURITY_CONTEXT_COLUMN_DEFAULT_FUNC, strlen(SECURITY_CONTEXT_COLUMN_DEFAULT_FUNC) - 2);
    pExpr->u.zToken[strlen(SECURITY_CONTEXT_COLUMN_DEFAULT_FUNC) - 2] = 0;
    sqlite3Dequote(pExpr->u.zToken);
    pExpr->flags |= EP_DblQuoted;
#if SQLITE_MAX_EXPR_DEPTH>0
    pExpr->nHeight = 1;
#endif
    pCol->pDflt = pExpr;
    pCol->zDflt = sqlite3DbStrNDup(db, SECURITY_CONTEXT_COLUMN_DEFAULT_FUNC
	      , strlen(SECURITY_CONTEXT_COLUMN_DEFAULT_FUNC));




    /* Loop through the columns of the table to see if any of them contain the token "hidden".
     ** If so, set the Column.isHidden flag and remove the token from
     ** the type string.  */
      // vsimple419
    int iCol;
    for (iCol = 0; iCol < p->nCol; iCol++) {
	char *zType = p->aCol[iCol].zType;
	char *zName = p->aCol[iCol].zName;
	int nType;
	int i = 0;
	if (!zType)
	continue;
	nType = sqlite3Strlen30(zType);
	if ( sqlite3StrNICmp("hidden", zType, 6)
			|| (zType[6] && zType[6] != ' ')) {
	    for (i = 0; i < nType; i++) {
		if ((0 == sqlite3StrNICmp(" hidden", &zType[i], 7))
				&& (zType[i + 7] == '\0' || zType[i + 7] == ' ')) {
		    i++;
		    break;
		}
	    }
	}
	if (i < nType) {
	    int j;
	    int nDel = 6 + (zType[i + 6] ? 1 : 0);
	    for (j = i; (j + nDel) <= nType; j++) {
		    zType[j] = zType[j + nDel];
	    }
	    if (zType[i] == '\0' && i > 0) {
		    assert(zType[i-1]==' ');
		    zType[i - 1] = '\0';
	    }
	    p->aCol[iCol].isHidden = 1;
	}
    }



   /* vsimple
    //assign security context to sql schema object
    //insert table context
    sqlite3NestedParse(pParse,
      "INSERT INTO %Q.%s (security_context, db, name) VALUES(getcon(), '%s', '%s')",
      pParse->db->aDb[iDb].zName, "selinux_context",
      pParse->db->aDb[iDb].zName, p->zName
    );
    sqlite3ChangeCookie(pParse, iDb);

    //add security context to columns
    for (iCol = 0; iCol < p->nCol; iCol++) {
    	sqlite3NestedParse(pParse,
    	  "INSERT INTO %Q.%s VALUES(getcon(), '%s', '%s', '%s')",
    	  pParse->db->aDb[iDb].zName, "selinux_context",
    	  pParse->db->aDb[iDb].zName, p->zName, p->aCol[iCol].zName
    	);
    }
    sqlite3ChangeCookie(pParse, iDb);

    sqlite3NestedParse(pParse,
      "INSERT INTO %Q.%s VALUES(getcon(), '%s', '%s', '%s')",
      pParse->db->aDb[iDb].zName, "selinux_context",
      pParse->db->aDb[iDb].zName, p->zName, "ROWID"
    );
    sqlite3ChangeCookie(pParse, iDb);

    */

     // vsimple420 printf("hidden column is %d, %s: %s: %s: %s\n", IsHiddenColumn(&p->aCol[p->nCol-1])?1:0, p->aCol[p->nCol-1].zName, p->aCol[p->nCol-1].zType, p->aCol[p->nCol-1].zDflt, p->aCol[p->nCol-1].pDflt);

    return SQLITE_OK;
}


int sqlite3SelinuxInit(sqlite3 *db) {

    int rc = 0;

    rc = initializeSeSqliteObjects(db);

    if(rc == SQLITE_OK)
	rc =sqlite3_set_add_extra_column(db, create_security_context_column, db);

    return rc;
}
