#ifndef _auth_sqlite_
#define _auth_sqlite_

#include <string>

extern "C" {
#include "sqlite3.h"
#include <unistd.h>
#include <string.h>
}

int db_exists();
/* failure returns 0, success returns 1 */
int auth_sqlite3(const std::string& username, const std::string& password);

#endif
