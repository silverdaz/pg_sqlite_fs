-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION sqlite_fs" to load this file. \quit

DO $$
BEGIN
   IF current_setting('sqlite_fs.location') IS NULL 
   THEN
      RAISE EXCEPTION 'Missing sqlite_fs settings'
      USING HINT = 'Add sqlite_fs.location = ''...'' in postgresql.conf ';
   END IF;
END;
$$;


-- CREATE OR REPLACE FUNCTION sqlite_fs_exec(text, text)
-- RETURNS boolean
-- AS 'MODULE_PATHNAME', 'pg_sqlite_fs_exec'
-- LANGUAGE C IMMUTABLE STRICT;
-- -- STRICT  = NULL parameters return NULL immediately


CREATE OR REPLACE FUNCTION make(text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_create'
LANGUAGE C IMMUTABLE STRICT;
-- STRICT  = NULL parameters return NULL immediately

CREATE OR REPLACE FUNCTION remove(text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_remove'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION insert_file(filename text, inode bigint,
                                       mountpoint text, relative_path text,
                                       header bytea, payload_size bigint, prepend bytea, append bytea)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_insert_file'
LANGUAGE C IMMUTABLE; -- NO STRICT

CREATE OR REPLACE FUNCTION delete_file(text, bigint)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_delete_file'
LANGUAGE C IMMUTABLE STRICT;
-- STRICT  = NULL parameters return NULL immediately

CREATE OR REPLACE FUNCTION insert_attribute(filename text,
                                            inode bigint, name text, value text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_insert_attribute'
LANGUAGE C IMMUTABLE; -- NO STRICT

CREATE OR REPLACE FUNCTION delete_attribute(filename text,
                                            inode bigint, name text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_delete_attribute'
LANGUAGE C IMMUTABLE STRICT;
-- STRICT  = NULL parameters return NULL immediately


CREATE OR REPLACE FUNCTION truncate_entries(text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_truncate_entries'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION truncate_files(text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_truncate_files'
LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION truncate_attributes(text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_truncate_attributes'
LANGUAGE C IMMUTABLE STRICT;


CREATE OR REPLACE FUNCTION insert_entry(text, bigint, text, bigint,
		    		        ctime  bigint DEFAULT 0,
					mtime  bigint DEFAULT 0,
  					nlink  bigint DEFAULT 1,
   					size   bigint DEFAULT 0,
					is_dir boolean DEFAULT TRUE)
RETURNS void
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_insert_entry'
LANGUAGE C;

CREATE OR REPLACE FUNCTION delete_entry(text, bigint)
RETURNS SETOF bigint
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_delete_entry'
LANGUAGE C IMMUTABLE STRICT;
-- STRICT  = NULL parameters return NULL immediately

CREATE OR REPLACE FUNCTION insert_files(text, text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_insert_files'
LANGUAGE C IMMUTABLE STRICT;
-- STRICT  = NULL parameters return NULL immediately

CREATE OR REPLACE FUNCTION insert_entries(text, text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_sqlite_fs_insert_entries'
LANGUAGE C IMMUTABLE STRICT;
-- STRICT  = NULL parameters return NULL immediately
