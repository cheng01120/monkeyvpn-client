#include "auth_sqlite3.hpp"
#include <iostream>

static const char *db_path = "/etc/mvpn.db";

int db_exists() {
	int retval = 0;
	FILE *fp = fopen(db_path, "r");
	if(fp) {
		retval = 1;
		fclose(fp);
	}

	return retval;
}


/* failure returns 0, success returns 1 */
int auth_sqlite3(const std::string& username, const std::string& password) {
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	int retval = 0;
	const char* password_hash;
	char *result;

	rc = sqlite3_open(db_path, &db);
	if(rc != SQLITE_OK) return 0;

	rc = sqlite3_prepare_v2(
		db, "select password from shadow where username = ?", -1, &res, 0);
	sqlite3_bind_text(res, 1, username.c_str(), -1, SQLITE_STATIC);
	rc = sqlite3_step(res);
	if (rc != SQLITE_ROW) goto OUT;

	password_hash = (const char *)sqlite3_column_text(res, 0);
	result = crypt(password.c_str(), password_hash);

	if(strncmp(result, password_hash, strlen(password_hash)) == 0) { 
		retval = 1;
	}

OUT:
	sqlite3_finalize(res);
	sqlite3_close(db);
	return retval;
}
