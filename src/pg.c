/*-------------------------------------------------------------------------
 *
 * src/pg_sqlite_fs.c
 *
 * Extension for creating an SQLite DB and execute a query in it,
 * to represent a file system over Crypt4GH-encrypted payloads
 * See documentation: https://www.postgresql.org/docs/current/xfunc-c.html
 *
 * To be used in combination with https://github.com/silverdaz/crypt4gh-sqlite
 *
 *-------------------------------------------------------------------------
 */

#include <sys/stat.h>
#include <unistd.h>

#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h" /* for text_to_cstring */
#include "utils/guc.h"

#include "funcapi.h"
#include "executor/spi.h"
#include "pgstat.h"
#include "tcop/utility.h"
#include "utils/memutils.h"

#include "sqlite3.h"

PG_MODULE_MAGIC; /* only one time */

/* logging */
#define F(fmt, ...)  elog(FATAL,  "============ " fmt, ##__VA_ARGS__)
#define E(fmt, ...)  elog(ERROR,  "============ " fmt, ##__VA_ARGS__)
#define W(fmt, ...)  elog(WARNING,"============ " fmt, ##__VA_ARGS__)
#define N(fmt, ...)  elog(NOTICE, "============ " fmt, ##__VA_ARGS__)
#define L(fmt, ...)  elog(LOG,    "============ " fmt, ##__VA_ARGS__)
#define D1(fmt, ...) elog(DEBUG1, "============ " fmt, ##__VA_ARGS__)
#define D2(fmt, ...) elog(DEBUG2, "============ " fmt, ##__VA_ARGS__)
#define D3(fmt, ...) elog(DEBUG3, "============ " fmt, ##__VA_ARGS__)
#define D4(fmt, ...) elog(DEBUG4, "============ " fmt, ##__VA_ARGS__)
#define D5(fmt, ...) elog(DEBUG5, "============ " fmt, ##__VA_ARGS__)

#define SQLITE_FS_LOCATION "sqlite_fs.location"

/* global settings */
static char* pg_sqlite_fs_location = NULL;

void _PG_init(void);
static char * convert_and_check_path(text *arg);

static bool
check_hook(char **newval, void **extra, GucSource source)
{

  D1("Check " SQLITE_FS_LOCATION " [%d]: newval %s", (int)source, (char*)*newval);

  if (source == PGC_S_DEFAULT){
    GUC_check_errmsg("%s ignored when setting default value", SQLITE_FS_LOCATION);
    GUC_check_errhint("%s can only be set from postgres.conf.", SQLITE_FS_LOCATION);
    return true;
  }

  if (source != PGC_S_FILE){
    GUC_check_errmsg("%s ignored when source is not %d", SQLITE_FS_LOCATION, PGC_S_FILE);
    GUC_check_errhint("%s can only be set from postgres.conf.", SQLITE_FS_LOCATION);
    return false;
  }

  if (*newval == NULL || **newval == '\0'){
    GUC_check_errmsg("%s can't be empty.", SQLITE_FS_LOCATION);
    return false;
  }

  if(!is_absolute_path(*newval)){
    D1("%s = '%s' is not an absolute path", SQLITE_FS_LOCATION, *newval);
    GUC_check_errmsg("%s must be an absolute path: %s", SQLITE_FS_LOCATION, *newval);
    return false;
  }

  /* Since canonicalize_path never enlarges the string, we can just modify newval in-place. */
  D3("canonicalize");
  canonicalize_path(*newval);

  /* Do not allow modifying the DataDir */
  if (path_is_prefix_of_path(DataDir, *newval)){
    D1("%s = '%s' is inside DataDir: %s", SQLITE_FS_LOCATION, *newval, DataDir);
    GUC_check_errmsg("%s cannot be inside the DataDir %s", *newval, DataDir);
    return false;
  }

  /* Finally, we don't bother removing the trailing / */
  return true;
}


/*
 * This gets called when the library file is loaded.
 * Similar to dlopen
 */
void
_PG_init(void)
{
  DefineCustomStringVariable(SQLITE_FS_LOCATION,
			     gettext_noop("The sqlite_fs top directory."),
			     NULL,
			     &pg_sqlite_fs_location,
			     NULL, /* no default */
			     PGC_USERSET,
 			     0,
			     check_hook, NULL, NULL);
}

/*
 * check if arg path is allowed
 * Seel https://github.com/postgres/postgres/blob/master/contrib/adminpack/adminpack.c#L389
 */
static char *
convert_and_check_path(text *arg)
{
  char	*path = text_to_cstring(arg);
  D3("Checking and converting %s", path);

  canonicalize_path(path);	/* path can change length here */
  
  if (!is_absolute_path(path))
    ereport(ERROR,
	    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
	     errmsg("path \"%s\" must be absolute", path)));

  /* Allow absolute paths if within pg_sqlite_fs_location */
  if (pg_sqlite_fs_location == NULL)
    ereport(ERROR,
	    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
	     errmsg("\"%s\" is not set or invalid | current value: %s", SQLITE_FS_LOCATION, pg_sqlite_fs_location)));

  if (!path_is_prefix_of_path(pg_sqlite_fs_location, path))
    ereport(ERROR,
	    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
	     errmsg("path \"%s\" must be below the \"%s\" directory: %s", path, SQLITE_FS_LOCATION, pg_sqlite_fs_location)));
  
  return path;
}


PG_FUNCTION_INFO_V1(pg_sqlite_fs_create);
Datum
pg_sqlite_fs_create(PG_FUNCTION_ARGS)
{

  int rc = 1;
  char* db_path;
  char* err = NULL;
  sqlite3 *db;
  mode_t m;

  if(PG_NARGS() != 1){
    E("Invalid number of arguments: expected 1, got %d", PG_NARGS());
    PG_RETURN_BOOL(false);
  }

  if(PG_ARGISNULL(0)){
    E("Null arguments not accepted");
    PG_RETURN_BOOL(false);
  }

  db_path = convert_and_check_path(PG_GETARG_TEXT_PP(0)); // allocated in the function context: will be cleaned by PG

  m = umask(0007);
  D2("Database open: %s | mask: %o", db_path, m);

  rc = sqlite3_open(db_path, &db); // SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE

  if( rc ) {
    N("Can't open database %s: %s", db_path, sqlite3_errmsg(db));
    rc = 1;
    goto bailout;
  }

  D1("Database open: %s", db_path);

  /* Execute SQL statement */
  rc = sqlite3_exec(db,
                    "CREATE TABLE IF NOT EXISTS files ("
		    "  inode         INT64 PRIMARY KEY,"
		    "  mountpoint    text,"
		    "  rel_path      text,"
		    "  header        BLOB,"
		    "  payload_size  INT64 NOT NULL DEFAULT 0," // (decrypted) size on disk
		    "  prepend       BLOB,"
		    "  append        BLOB"
		    ");",
		    NULL, NULL, &err);
   
  if( rc != SQLITE_OK ){
    N("SQL error creating files table: %s", err);
    rc = 2;
    goto bailout;
  }

  rc = sqlite3_exec(db,
                    "CREATE TABLE IF NOT EXISTS extended_attributes ("
                    "    inode             INT64 NOT NULL,"
                    "    name              text NOT NULL,"
                    "    value             text NOT NULL,"
                    "    PRIMARY KEY(inode,name)"
                    ");",
		    NULL, NULL, &err);
   
  if( rc != SQLITE_OK ){
    N("SQL error creating the extended_attributes table: %s", err);
    rc = 2;
    goto bailout;
  }

  rc = sqlite3_exec(db,
		    "CREATE TABLE IF NOT EXISTS entries ("
		    "    inode             INT64 NOT NULL PRIMARY KEY,"
                    "    name              text NOT NULL,"
    		    "    parent_inode      INT64 NOT NULL REFERENCES entries(inode),"
    		    "    ctime             INT64 NOT NULL DEFAULT 0,"
    		    "    mtime             INT64 NOT NULL DEFAULT 0,"
    		    "    nlink             INT NOT NULL DEFAULT 1,"
    		    "    size              INT64 NOT NULL DEFAULT 0,"
		    "    is_dir            INT NOT NULL DEFAULT 1" // -- if 0, then JOIN with files table
		    ");",
		    NULL, NULL, &err);
   
  if( rc != SQLITE_OK ){
    N("SQL error creating entries table: %s", err);
    rc = 2;
    goto bailout;
  }

  rc = sqlite3_exec(db,
		    "CREATE UNIQUE INDEX IF NOT EXISTS names ON entries(parent_inode, name);",
		    NULL, NULL, &err);
   
  if( rc != SQLITE_OK ){
    N("SQL error creating the entries's index: %s", err);
    rc = 2;
    goto bailout;
  }

  rc = sqlite3_exec(db,
		    "CREATE INDEX IF NOT EXISTS listing ON entries(parent_inode, inode, name);",
		    NULL, NULL, &err);
   
  if( rc != SQLITE_OK ){
    N("SQL error creating the listing's index: %s", err);
    rc = 2;
    goto bailout;
  }

  rc = sqlite3_exec(db,
		    "INSERT INTO entries(inode, name, parent_inode) VALUES (1, '/', 1) ON CONFLICT DO NOTHING;",
		    NULL, NULL, &err);
   
  if( rc != SQLITE_OK ){
    N("SQL error adding the root entry: %s", err);
    rc = 2;
    goto bailout;
  }

  D3("Successfully created: %s", db_path);
  rc = 0; // success
  
bailout:
  if(err) sqlite3_free(err);
  sqlite3_close(db);
  (void)umask(m); // reset back to old mask
  PG_RETURN_BOOL(((rc)?false:true));
}


PG_FUNCTION_INFO_V1(pg_sqlite_fs_remove);
Datum
pg_sqlite_fs_remove(PG_FUNCTION_ARGS)
{

  char* db_path;

  if(PG_NARGS() != 1){
    E("Invalid number of arguments: expected 1, got %d", PG_NARGS());
    PG_RETURN_BOOL(false);
  }

  if(PG_ARGISNULL(0)){
    E("Null arguments not accepted");
    PG_RETURN_BOOL(false);
  }

  db_path = convert_and_check_path(PG_GETARG_TEXT_PP(0)); // allocated in the function context: will be cleaned by PG

  PG_RETURN_BOOL((unlink(db_path))?false:true);
}


PG_FUNCTION_INFO_V1(pg_sqlite_fs_insert_file);
Datum
pg_sqlite_fs_insert_file(PG_FUNCTION_ARGS)
{

  int rc = 1;
  char* db_path;
  sqlite3 *db;
  sqlite3_stmt *stmt = NULL;
  text  *rpath = NULL;
  text  *mnt = NULL;
  bytea *header = NULL;
  bytea *prepend = NULL;
  bytea *append = NULL;

  if(PG_NARGS() != 8){
    E("Invalid number of arguments: expected 8, got %d", PG_NARGS());
    PG_RETURN_BOOL(false);
  }

  if(PG_ARGISNULL(0) || PG_ARGISNULL(1)){
    E("First 2 arguments can't be null");
    PG_RETURN_BOOL(false);
  }

  db_path = convert_and_check_path(PG_GETARG_TEXT_PP(0)); // allocated in the function context: will be cleaned by PG

  rc = sqlite3_open(db_path, &db); // SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE

  if( rc ) {
    N("Can't open database %s: %s", db_path, sqlite3_errmsg(db));
    rc = 1;
    goto bailout;
  }

  D2("Database open: %s", db_path);

  /* SQL statement */
  // 1: inode
  if(!PG_ARGISNULL(2)) mnt = PG_GETARG_TEXT_PP(2);
  if(!PG_ARGISNULL(3)) rpath = PG_GETARG_TEXT_PP(3);
  if(!PG_ARGISNULL(4)) header = PG_GETARG_BYTEA_PP(4);
  // 5: payload_size
  if(!PG_ARGISNULL(6)) prepend = PG_GETARG_BYTEA_PP(6);
  if(!PG_ARGISNULL(7)) append = PG_GETARG_BYTEA_PP(7);

  D1("Inserting %.*s/%.*s", (int)VARSIZE_ANY_EXHDR(mnt), VARDATA_ANY(mnt), (int)VARSIZE_ANY_EXHDR(rpath), VARDATA_ANY(rpath));

  rc = sqlite3_prepare_v2(db,
			  "INSERT INTO files(inode,mountpoint,rel_path,header,payload_size,prepend,append)"
			  " VALUES(?,?,?,?,?,?,?)"
			  " ON CONFLICT(inode) DO UPDATE SET mountpoint=excluded.mountpoint,"
			                                   " rel_path=excluded.rel_path,"
			                                   " header=excluded.header,"
			                                   " payload_size=excluded.payload_size,"
			                                   " prepend=excluded.prepend,"
			                                   " append=excluded.append;",
			  -1, &stmt, NULL);
  if( rc != SQLITE_OK ) {
    N("Error preparing statement: %s", sqlite3_errmsg(db));
    rc = 1;
    goto bailout;
  }

  /* Bind arguments */
  D2("Binding arguments for inserting file");
  rc = (sqlite3_bind_int64(stmt, 1, PG_GETARG_INT64(1)) ||
	( (PG_ARGISNULL(2)) ? sqlite3_bind_null(stmt, 2)
	                    : sqlite3_bind_text(stmt, 2, VARDATA_ANY(mnt), (int)VARSIZE_ANY_EXHDR(mnt), SQLITE_STATIC)) || // we handle destruction
	( (PG_ARGISNULL(3)) ? sqlite3_bind_null(stmt, 3)
 	                    : sqlite3_bind_text(stmt, 3, VARDATA_ANY(rpath), (int)VARSIZE_ANY_EXHDR(rpath), SQLITE_STATIC)) || // we handle destruction
	( (PG_ARGISNULL(4)) ? sqlite3_bind_null(stmt, 4)
	                    : sqlite3_bind_blob(stmt, 4, VARDATA_ANY(header), (int)VARSIZE_ANY_EXHDR(header), SQLITE_STATIC) ) ||
	sqlite3_bind_int64(stmt, 5,  ((PG_ARGISNULL(5)) ? 0 : PG_GETARG_INT64(5))) ||
	( (PG_ARGISNULL(6)) ? sqlite3_bind_null(stmt, 6)
	                    : sqlite3_bind_blob(stmt, 6, VARDATA_ANY(prepend), (int)VARSIZE_ANY_EXHDR(prepend), SQLITE_STATIC) ) ||
	                      // sqlite3_bind_blob64 is too much, come on!
	( (PG_ARGISNULL(7)) ? sqlite3_bind_null(stmt, 7)
	                    : sqlite3_bind_blob(stmt, 7, VARDATA_ANY(append), (int)VARSIZE_ANY_EXHDR(append), SQLITE_STATIC) )
	                      // sqlite3_bind_blob64 is too much, come on!
	);
  if( rc != SQLITE_OK ){
    N("SQL error binding arguments: %s", sqlite3_errmsg(db));
    rc = 2;
    goto bailout;
  }

  {
    char* expanded_sql = sqlite3_expanded_sql(stmt);
    D1("expanded statement: %s", expanded_sql);
    sqlite3_free(expanded_sql);
  }

  /* Execute SQL prepared statement */
  D2("Execute statement for insert file");
  rc = sqlite3_step(stmt);
  if( rc != SQLITE_DONE ){
    N("SQL error inserting the file: %s | error: %d", sqlite3_errmsg(db), rc);
    rc = 3;
    goto bailout;
  }

  D3("Successfully inserted file %ld", PG_GETARG_INT64(1));
  rc = 0; // success
  
bailout:
  if(stmt) sqlite3_finalize(stmt);
  sqlite3_close(db);
  PG_RETURN_BOOL(((rc)?false:true));
}


PG_FUNCTION_INFO_V1(pg_sqlite_fs_insert_entry);
Datum
pg_sqlite_fs_insert_entry(PG_FUNCTION_ARGS)
{

  int rc = 1;
  char* db_path;
  sqlite3 *db;
  sqlite3_stmt *stmt = NULL;
  text* name;
  int64 inode, parent_inode;


  if(PG_NARGS() < 4){
    E("Invalid number of arguments: expected at least 4, got %d", PG_NARGS());
    PG_RETURN_BOOL(false);
  }

  if(PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2) || PG_ARGISNULL(3)){
    E("Null arguments not accepted");
    PG_RETURN_BOOL(false);
  }

  db_path = convert_and_check_path(PG_GETARG_TEXT_PP(0)); // allocated in the function context: will be cleaned by PG

  rc = sqlite3_open(db_path, &db); // SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE

  if( rc ) {
    N("Can't open database %s: %s", db_path, sqlite3_errmsg(db));
    rc = 1;
    goto bailout;
  }

  D2("Database open: %s", db_path);

  inode = PG_GETARG_INT64(1);
  name = PG_GETARG_TEXT_PP(2);
  parent_inode = PG_GETARG_INT64(3);
  D2("Inserting entry [%ld]/%*s | %ld", parent_inode, (int)VARSIZE_ANY_EXHDR(name), VARDATA_ANY(name), inode);

  /* SQL statement */
  rc = sqlite3_prepare_v2(db,
			  "INSERT INTO entries(inode,name,parent_inode,ctime,mtime,nlink,size,is_dir)"
			  "VALUES(?,?,?,?,?,?,?,?)"
			  //" ON CONFLICT(inode) DO NOTHING;",
			  " ON CONFLICT(inode) DO UPDATE SET name=excluded.name,"
			                                   " parent_inode=excluded.parent_inode,"
			                                   " ctime=excluded.ctime,"
			                                   " mtime=excluded.mtime,"
			                                   " nlink=excluded.nlink,"
			                                   " size=excluded.size,"
			                                   " is_dir=excluded.is_dir;",
			  -1, &stmt, NULL);
  if( rc != SQLITE_OK ) {
    N("Error preparing statement: %s", sqlite3_errmsg(db));
    rc = 1;
    goto bailout;
  }

  /* Bind arguments */
  D2("Binding arguments while inserting entry");

  rc = rc ||
    (sqlite3_bind_int64(stmt, 1, inode) ||
     sqlite3_bind_text( stmt, 2, VARDATA_ANY(name), (int)VARSIZE_ANY_EXHDR(name), SQLITE_STATIC) || // we handle destruction
     sqlite3_bind_int64(stmt, 3, parent_inode) ||
     sqlite3_bind_int64(stmt, 4, PG_GETARG_INT64(4)) || // ctime
     sqlite3_bind_int64(stmt, 5, PG_GETARG_INT64(5)) || // mtime
     sqlite3_bind_int64(stmt, 6, PG_GETARG_INT64(6)) || // nlink
     sqlite3_bind_int64(stmt, 7, PG_GETARG_INT64(7)) || // size
     sqlite3_bind_int(  stmt, 8, (PG_GETARG_BOOL(8))?1:0) // is_dir
     );
  if( rc != SQLITE_OK ) {
    N("Error binding main arguments: %s", sqlite3_errmsg(db));
    rc = 2;
    goto bailout;
  }

  /* Execute SQL prepared statement */
  D2("Execute statement for insert entry");
  rc = sqlite3_step(stmt);
  if( rc != SQLITE_DONE ){
    N("SQL error inserting entry: %ld | error %d: %s", inode, rc, sqlite3_errstr(rc));
    rc = 3;
    goto bailout;
  }

  D3("Successfully inserted entry %ld ([%ld]/%*s)", inode, parent_inode, (int)VARSIZE_ANY_EXHDR(name), VARDATA_ANY(name));
  rc = 0; // success
  
bailout:
  if(stmt) sqlite3_finalize(stmt);
  sqlite3_close(db);
  PG_RETURN_BOOL(((rc)?false:true));
}


PG_FUNCTION_INFO_V1(pg_sqlite_fs_delete_file);
Datum
pg_sqlite_fs_delete_file(PG_FUNCTION_ARGS)
{
    int rc = 1;
    char* db_path;
    int64 inode;
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;

    db_path = convert_and_check_path(PG_GETARG_TEXT_PP(0)); // allocated in the function context: will be cleaned by PG
    N("Opening database %s", db_path);

    rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE, NULL);
    if( rc != SQLITE_OK )
      E("SQL error opening database: %s | error %d: %s", db_path, rc, sqlite3_errstr(rc));
	
    /* rc = sqlite3_prepare_v3(db,
			    "DELETE FROM files WHERE inode = ?;",
			    -1, SQLITE_PREPARE_PERSISTENT, // reused
			    &stmt, NULL); */
    rc = sqlite3_prepare_v2(db,
			   "DELETE FROM files WHERE inode = ?;",
			   -1, &stmt, NULL);

    inode = PG_GETARG_INT64(1);

    rc = sqlite3_bind_int64(stmt, 1, inode);
    if( rc != SQLITE_OK ) {
      N("Error binding main arguments: %s", sqlite3_errmsg(db));
      goto bailout;
    }

    /* Execute SQL prepared statement */
    D1("Execute statement for deleting a file");
    rc = sqlite3_step(stmt);
    if( rc != SQLITE_DONE ){
      N("Error: %s", sqlite3_errmsg(db));
      rc = 1;
    }
    rc = 0; // success

bailout:
    if(stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    PG_RETURN_BOOL(((rc)?false:true));
}

PG_FUNCTION_INFO_V1(pg_sqlite_fs_delete_entry);
Datum
pg_sqlite_fs_delete_entry(PG_FUNCTION_ARGS)
{
    int rc = 1;
    char* db_path;
    int64 inode;
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;

    db_path = convert_and_check_path(PG_GETARG_TEXT_PP(0)); // allocated in the function context: will be cleaned by PG
    N("Opening database %s", db_path);

    rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE, NULL);
    if( rc != SQLITE_OK )
      E("SQL error opening database: %s | error %d: %s", db_path, rc, sqlite3_errstr(rc));
	
    rc = sqlite3_prepare_v2(db,
			   "DELETE FROM entries WHERE inode = ?1 OR parent_inode = ?1;",
			    // Note: in case of directory: missing some sub-directories
			    // => Use recursive with condition
			   -1, &stmt, NULL);

    inode = PG_GETARG_INT64(1);

    rc = sqlite3_bind_int64(stmt, 1, inode);
    if( rc != SQLITE_OK ) {
      N("Error binding main arguments: %s", sqlite3_errmsg(db));
      goto bailout;
    }

    /* Execute SQL prepared statement */
    D1("Execute statement for deleting an entry");
    while(1){
      rc = sqlite3_step(stmt);
      if( rc == SQLITE_DONE ){
	rc = 0; // success
	goto bailout;
      }
      if( rc != SQLITE_ROW ) {
	N("Error: %s", sqlite3_errmsg(db));
	rc = 1;
	goto bailout;
      }
    }

bailout:
    if(stmt) sqlite3_finalize(stmt);
    sqlite3_close(db);
    PG_RETURN_BOOL(((rc)?false:true));
}


static bool
pg_sqlite_fs_truncate_table(PG_FUNCTION_ARGS, const char* sql)
{
    int rc = 1;
    char* db_path;
    sqlite3 *db;
    char* err = NULL;

    db_path = convert_and_check_path(PG_GETARG_TEXT_PP(0)); // allocated in the function context: will be cleaned by PG
    N("Opening database %s", db_path);

    rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE, NULL);
    if( rc != SQLITE_OK )
      E("SQL error opening database: %s | error %d: %s", db_path, rc, sqlite3_errstr(rc));
	
    D1("Execute statement: %s", sql);
    rc = sqlite3_exec(db, sql, NULL, NULL, &err);
   
    if( rc != SQLITE_OK )
      N("SQL error for '%s' in %s: %s", sql, db_path, err);

    if(err)
      sqlite3_free(err);

    sqlite3_close(db);

    return (rc == SQLITE_OK)?true:false;
}

PG_FUNCTION_INFO_V1(pg_sqlite_fs_truncate_entries);
Datum
pg_sqlite_fs_truncate_entries(PG_FUNCTION_ARGS)
{
  PG_RETURN_BOOL(pg_sqlite_fs_truncate_table(fcinfo, "DELETE FROM entries WHERE inode > 1"));
}

PG_FUNCTION_INFO_V1(pg_sqlite_fs_truncate_files);
Datum
pg_sqlite_fs_truncate_files(PG_FUNCTION_ARGS)
{
  // See https://www.sqlite.org/lang_delete.html#the_truncate_optimization
  PG_RETURN_BOOL(pg_sqlite_fs_truncate_table(fcinfo, "DELETE FROM files"));
}

PG_FUNCTION_INFO_V1(pg_sqlite_fs_truncate_attributes);
Datum
pg_sqlite_fs_truncate_attributes(PG_FUNCTION_ARGS)
{
  PG_RETURN_BOOL(pg_sqlite_fs_truncate_table(fcinfo, "DELETE FROM extended_attributes"));
}


PG_FUNCTION_INFO_V1(pg_sqlite_fs_exec);
Datum
pg_sqlite_fs_exec(PG_FUNCTION_ARGS)
{
  int rc = 1;
  char* db_path;
  char* sql;
  char* err = NULL;
  sqlite3 *db;

  if(PG_NARGS() != 2){
    E("Invalid number of arguments: expected 2, got %d", PG_NARGS());
    PG_RETURN_BOOL(false);
  }

  if(PG_ARGISNULL(0) || PG_ARGISNULL(1)){
    E("Null arguments not accepted");
    PG_RETURN_BOOL(false);
  }

  db_path = convert_and_check_path(PG_GETARG_TEXT_PP(0)); // allocated in the function context: will be cleaned by PG

  sql = text_to_cstring(PG_GETARG_TEXT_PP(1));

  if(!sql){ E("Allocation failed"); PG_RETURN_BOOL(false); }

  rc = sqlite3_open(db_path, &db); // SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE

  if( rc ) {
    N("Can't open database %s: %s", db_path, sqlite3_errmsg(db));
    rc = 1;
    goto bailout;
  }

  N("Database open: %s", db_path);

  /* Execute SQL statement */
  rc = sqlite3_exec(db, sql, NULL, NULL, &err);
   
  if( rc != SQLITE_OK ){
    N("SQL error in %s: %s", db_path, err);
    rc = 2;
    goto bailout;
  }

  N("SQL statement executed successfully: %s", sql);
  rc = 0; // success
  
bailout:
  if(err) sqlite3_free(err);
  sqlite3_close(db);
  PG_RETURN_BOOL(((rc)?false:true));
}



/*-------------------------------------------------------------------------
 *
 * Open from file descriptor:
 * - https://www.sqlite.org/forum/draft2/info/c15bf2e7df289a5f41c7402b2e4f7323385e38e2a001a1fea42ccc8071a8c2d8
 *
 *-------------------------------------------------------------------------
 */

#define SQLITE_FS_CHECK_TYPE(p, t, n) if(TupleDescAttr(SPI_tuptable->tupdesc, (p))->atttypid != (t)){ W("SPI_execute: invalid type %d: %s", (p), (n)); rc = 4; goto bailout_spi; }

PG_FUNCTION_INFO_V1(pg_sqlite_fs_insert_files);
Datum
pg_sqlite_fs_insert_files(PG_FUNCTION_ARGS)
{

  int rc = 1;
  char* db_path;
  sqlite3 *db;
  sqlite3_stmt *stmt = NULL;
  char *sql = NULL;
  int i;

  if(PG_NARGS() != 2){
    E("Invalid number of arguments: expected 2, got %d", PG_NARGS());
    PG_RETURN_BOOL(false);
  }

  if(PG_ARGISNULL(0) || PG_ARGISNULL(1)){
    E("Null arguments not accepted");
    PG_RETURN_BOOL(false);
  }

  db_path = convert_and_check_path(PG_GETARG_TEXT_PP(0)); // allocated in the function context: will be cleaned by PG

  rc = sqlite3_open(db_path, &db); // SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE

  if( rc ) {
    N("Can't open database %s: %s", db_path, sqlite3_errmsg(db));
    PG_RETURN_BOOL(false);
  }

  D2("Database open: %s", db_path);

  /* Start SQLite transaction */
  rc = sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
  if( rc != SQLITE_OK ) {
    N("Error starting transaction: %s", sqlite3_errmsg(db));
    rc = 1;
    goto close_sqlite_db;
  }

  /* SQL prepared statement */
  rc = sqlite3_prepare_v2(db,
			  "INSERT INTO files(inode,mountpoint,rel_path,header,payload_size,prepend,append)"
			  " VALUES(?,?,?,?,?,?,?)"
			  " ON CONFLICT(inode) DO UPDATE SET mountpoint=excluded.mountpoint,"
			  "                                  rel_path=excluded.rel_path,"
			  "                                  header=excluded.header,"
			  "                                  payload_size=excluded.payload_size,"
			  "                                  prepend=excluded.prepend,"
			  "                                  append=excluded.append;",
			  -1, &stmt, NULL);
  if( rc != SQLITE_OK ) {
    N("Error preparing statement: %s", sqlite3_errmsg(db));
    rc = 1;
    goto close_sqlite_stmt;
  }

  /* Connect */
  rc = SPI_connect();
  if (rc != SPI_OK_CONNECT){
    W("SPI_connect failed: error code %d", rc);
    goto close_sqlite_stmt;
  }

  /* Execute the query */
  sql = text_to_cstring(PG_GETARG_TEXT_PP(1)); /* clean on exiting the function */
  if(!sql){ // no mem
    rc = 1;
    goto bailout_spi;
  }
  pgstat_report_activity(STATE_RUNNING, sql); 

  /* We can now execute queries via SPI */
  rc = SPI_execute(sql, true /* read_only */, 0 /* count */);

  if (rc != SPI_OK_SELECT){
    W("SPI_execute failed: error code %d", rc);
    rc = 2;
    goto bailout_spi;
  }

  /* Check the SQL statement to be executed */ 
  if(SPI_tuptable->tupdesc->natts != 4){
    W("SPI_execute returns %d fields. Expecting 4", SPI_tuptable->tupdesc->natts);
    rc = 3;
    goto bailout_spi;
  }

  SQLITE_FS_CHECK_TYPE(0, INT8OID, "inode");
  SQLITE_FS_CHECK_TYPE(1, TEXTOID, "mountpoint");
  SQLITE_FS_CHECK_TYPE(2, TEXTOID, "rel_path");
  SQLITE_FS_CHECK_TYPE(3, BYTEAOID, "header");
  SQLITE_FS_CHECK_TYPE(4, INT8OID, "payload_size");
  SQLITE_FS_CHECK_TYPE(5, BYTEAOID, "prepend");
  SQLITE_FS_CHECK_TYPE(6, BYTEAOID, "append");


  for(i=0 ; i < SPI_processed; i++){

    bytea *header;
    bytea *prepend;
    bytea *append;
    text *path;
    text *mountpoint;
    int64 inode, payload_size;
    bool isnull, header_isnull, prepend_isnull, append_isnull;

    rc = 1;

    inode = DatumGetUInt64(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1, &isnull));
    if (isnull){
      W("the inode field can't be NULL");
      goto bailout_spi;
    }

    mountpoint = DatumGetTextPP(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 2, &isnull));
    if (isnull){
      W("The mountpoint field can't be NULL");
      goto bailout_spi;
    }

    path = DatumGetTextPP(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 3, &isnull));
    if (isnull){
      W("The path field can't be NULL");
      goto bailout_spi;
    }

    header = DatumGetByteaP(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 4, &header_isnull));
    payload_size = DatumGetUInt64(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 5, &isnull));
    if (isnull) payload_size = 0;
    prepend = DatumGetByteaP(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 6, &prepend_isnull));
    append = DatumGetByteaP(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 7, &append_isnull));

    /* Bind arguments */
    D2("Binding arguments for inserting file");
    rc = (sqlite3_bind_int64(stmt, 1, inode) ||
	  sqlite3_bind_text(stmt, 2, VARDATA_ANY(mountpoint), (int)VARSIZE_ANY_EXHDR(mountpoint), SQLITE_STATIC) || // we handle destruction
	  sqlite3_bind_text(stmt, 3, VARDATA_ANY(path)      , (int)VARSIZE_ANY_EXHDR(path)      , SQLITE_STATIC) || // we handle destruction
	  ( (header_isnull) ? sqlite3_bind_null(stmt, 4)
	                    : sqlite3_bind_blob(stmt, 4, VARDATA_ANY(header), (int)VARSIZE_ANY_EXHDR(header), SQLITE_STATIC) ) ||
	  sqlite3_bind_int64(stmt, 5, payload_size) ||
	  ( (prepend_isnull) ? sqlite3_bind_null(stmt, 6)
	                     : sqlite3_bind_blob(stmt, 6, VARDATA_ANY(prepend), (int)VARSIZE_ANY_EXHDR(prepend), SQLITE_STATIC) ) ||
	  ( (append_isnull) ? sqlite3_bind_null(stmt, 7)
	                    : sqlite3_bind_blob(stmt, 7, VARDATA_ANY(append), (int)VARSIZE_ANY_EXHDR(append), SQLITE_STATIC) )
	  );
    if( rc != SQLITE_OK ){
      N("SQL error binding arguments: %s", sqlite3_errmsg(db));
      rc = 6;
      goto bailout_spi;
    }

    /* Execute SQL prepared statement */
    D2("Execute statement for insert file");
    rc = sqlite3_step(stmt);
    if( rc != SQLITE_DONE ){
      N("SQL error inserting the file: %s | error: %d", sqlite3_errmsg(db), rc);
      rc = 3;
      goto bailout_spi;
    }

    sqlite3_reset(stmt);
    rc = 0;
  }

bailout_spi:

  /* finish the SQL statement */
  SPI_finish();
  debug_query_string = NULL;
  pgstat_report_stat(true);
  pgstat_report_activity(STATE_IDLE, NULL);


close_sqlite_stmt:

  if(stmt) sqlite3_finalize(stmt);

  /* Close the transaction */
  rc = sqlite3_exec(db, (rc)?"ROLLBACK;":"COMMIT;", NULL, NULL, NULL);
  if( rc != SQLITE_OK ) {
    N("Error closing transaction: %s", sqlite3_errmsg(db));
    rc = 1;
  } else
    rc = 0; // success
  
close_sqlite_db:
  sqlite3_close(db);

  PG_RETURN_BOOL(((rc)?false:true));
}



PG_FUNCTION_INFO_V1(pg_sqlite_fs_insert_entries);
Datum
pg_sqlite_fs_insert_entries(PG_FUNCTION_ARGS)
{

  int rc = 1;
  char* db_path;
  sqlite3 *db;
  sqlite3_stmt *stmt = NULL;
  char *sql = NULL;
  int i;
  bool isnull;

  if(PG_NARGS() != 2){
    E("Invalid number of arguments: expected 2, got %d", PG_NARGS());
    PG_RETURN_BOOL(false);
  }

  if(PG_ARGISNULL(0) || PG_ARGISNULL(1)){
    E("Null arguments not accepted");
    PG_RETURN_BOOL(false);
  }

  db_path = convert_and_check_path(PG_GETARG_TEXT_PP(0)); // allocated in the function context: will be cleaned by PG

  rc = sqlite3_open(db_path, &db); // SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE

  if( rc ) {
    N("Can't open database %s: %s", db_path, sqlite3_errmsg(db));
    PG_RETURN_BOOL(false);
  }

  D2("Database open: %s", db_path);

  /* Start SQLite transaction */
  rc = sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
  if( rc != SQLITE_OK ) {
    N("Error starting transaction: %s", sqlite3_errmsg(db));
    rc = 1;
    goto close_sqlite_db;
  }

  /* SQL prepared statement */
  rc = sqlite3_prepare_v2(db,
			  "INSERT INTO entries(inode,name,parent_inode,ctime,mtime,nlink,size,is_dir)"
			  "VALUES(?,?,?,?,?,?,?,?)"
			  //" ON CONFLICT(inode) DO NOTHING;",
			  " ON CONFLICT(inode) DO UPDATE SET "
			  "name=excluded.name,"
			  "parent_inode=excluded.parent_inode,"
			  "ctime=excluded.ctime,"
			  "mtime=excluded.mtime,"
			  "nlink=excluded.nlink,"
			  "size=excluded.size,"
			  "is_dir=excluded.is_dir;",
			  -1, &stmt, NULL);
  if( rc != SQLITE_OK ) {
    N("Error preparing statement: %s", sqlite3_errmsg(db));
    rc = 1;
    goto close_sqlite_stmt;
  }

  /* Connect */
  rc = SPI_connect();
  if (rc != SPI_OK_CONNECT){
    W("SPI_connect failed: error code %d", rc);
    goto close_sqlite_stmt;
  }

  /* Execute the query */
  sql = text_to_cstring(PG_GETARG_TEXT_PP(1)); /* clean on exiting the function */
  if(!sql){ // no mem
    rc = 1;
    goto bailout_spi;
  }
  pgstat_report_activity(STATE_RUNNING, sql); 

  /* We can now execute queries via SPI */
  rc = SPI_execute(sql, true /* read_only */, 0 /* count */);

  if (rc != SPI_OK_SELECT){
    W("SPI_execute failed: error code %d", rc);
    rc = 2;
    goto bailout_spi;
  }

  /* Check the SQL statement to be executed */ 
  if(SPI_tuptable->tupdesc->natts != 9){
    W("SPI_execute returns %d fields. Expecting 9", SPI_tuptable->tupdesc->natts);
    rc = 3;
    goto bailout_spi;
  }

  SQLITE_FS_CHECK_TYPE(0, INT8OID, "inode");
  SQLITE_FS_CHECK_TYPE(1, TEXTOID, "name");
  SQLITE_FS_CHECK_TYPE(2, INT8OID, "parent inode");
  SQLITE_FS_CHECK_TYPE(3, INT8OID, "created");
  SQLITE_FS_CHECK_TYPE(4, INT8OID, "modified");
  SQLITE_FS_CHECK_TYPE(5, INT4OID, "num_links");
  SQLITE_FS_CHECK_TYPE(6, INT8OID, "filesize");
  SQLITE_FS_CHECK_TYPE(7, BOOLOID, "is_dir");

  for(i=0 ; i < SPI_processed; i++){

    int64 inode, parent_inode, ctime, mtime, nlink, size;
    bool is_dir;
    text *name;

    rc = 1;

    inode = DatumGetUInt64(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1, &isnull));
    if (isnull){
      W("the inode field can't be NULL");
      goto bailout_spi;
    }
    name = DatumGetTextPP(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 2, &isnull));
    if (isnull){
      W("The name field can't be NULL");
      goto bailout_spi;
    }
    parent_inode = DatumGetUInt64(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 3, &isnull));
    if (isnull){
      W("the parent inode field can't be NULL");
      goto bailout_spi;
    }
    ctime = DatumGetUInt64(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 4, &isnull));
    if (isnull){
      W("the ctime field can't be NULL");
      goto bailout_spi;
    }
    mtime = DatumGetUInt64(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 5, &isnull));
    if (isnull){
      W("the mtime field can't be NULL");
      goto bailout_spi;
    }
    nlink = DatumGetUInt32(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 6, &isnull));
    if (isnull){
      W("the nlink field can't be NULL");
      goto bailout_spi;
    }
    size = DatumGetUInt64(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 7, &isnull));
    if (isnull){
      W("the size field can't be NULL");
      goto bailout_spi;
    }
    is_dir = DatumGetBool(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 8, &isnull));
    if (isnull){
      W("the is_dir field can't be NULL");
      goto bailout_spi;
    }

    /* Bind arguments */
    D2("Binding arguments for inserting file");
    rc = (sqlite3_bind_int64(stmt, 1, inode) ||
	  sqlite3_bind_text( stmt, 2, VARDATA_ANY(name), (int)VARSIZE_ANY_EXHDR(name), SQLITE_STATIC) || // we handle destruction
	  sqlite3_bind_int64(stmt, 3, parent_inode) ||
	  sqlite3_bind_int64(stmt, 4, ctime) ||
	  sqlite3_bind_int64(stmt, 5, mtime) ||
	  sqlite3_bind_int(  stmt, 6, nlink) ||
	  sqlite3_bind_int64(stmt, 7, size) ||
	  sqlite3_bind_int(  stmt, 8, (is_dir)?1:0)
	  );
    if( rc != SQLITE_OK ){
      N("SQL error binding arguments: %s", sqlite3_errmsg(db));
      rc = 6;
      goto bailout_spi;
    }

    /* Execute SQL prepared statement */
    D2("Execute statement for insert file");
    rc = sqlite3_step(stmt);
    if( rc != SQLITE_DONE ){
      N("SQL error inserting the file: %s | error: %d", sqlite3_errmsg(db), rc);
      rc = 3;
      goto bailout_spi;
    }

    sqlite3_reset(stmt);
    rc = 0;
  }

bailout_spi:

  /* finish the SQL statement */
  SPI_finish();
  debug_query_string = NULL;
  pgstat_report_stat(true);
  pgstat_report_activity(STATE_IDLE, NULL);


close_sqlite_stmt:

  if(stmt) sqlite3_finalize(stmt);

  /* Close the transaction */
  rc = sqlite3_exec(db, (rc)?"ROLLBACK;":"COMMIT;", NULL, NULL, NULL);
  if( rc != SQLITE_OK ) {
    N("Error closing transaction: %s", sqlite3_errmsg(db));
    rc = 1;
  } else
    rc = 0; // success
  
close_sqlite_db:
  sqlite3_close(db);

  PG_RETURN_BOOL(((rc)?false:true));
}
