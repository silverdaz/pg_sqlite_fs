ALTER SYSTEM SET sqlite_fs.location TO '/data/sqlite-boxes';
ALTER SYSTEM SET log_min_messages TO 'debug1';
SELECT pg_reload_conf();


CREATE TABLE IF NOT EXISTS public.entries (
    inode             bigint NOT NULL PRIMARY KEY,
    name              text NOT NULL,
    parent_inode      bigint NOT NULL REFERENCES entries(inode) ON DELETE CASCADE
                                                                NOT DEFERRABLE
								INITIALLY IMMEDIATE,
    created_at        timestamp(6) with time zone NOT NULL DEFAULT now(),
    modified_at       timestamp(6) with time zone NOT NULL DEFAULT now(),
    is_dir            boolean NOT NULL DEFAULT TRUE,
    size              bigint NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS names ON public.entries(parent_inode, name);

INSERT INTO public.entries(inode, name, parent_inode)
VALUES (1, '/', 1)
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS public.files (
  inode         bigint PRIMARY KEY REFERENCES public.entries(inode) ON DELETE CASCADE
                                                                    NOT DEFERRABLE
								    INITIALLY IMMEDIATE,
  mountpoint    text,
  rel_path      text,
  payload_size  bigint,
  prepend       bytea,
  append        bytea
);



CREATE SCHEMA sqlite_fs;

CREATE EXTENSION pg_sqlite_fs SCHEMA sqlite_fs;

CREATE OR REPLACE FUNCTION sqlite_fs.generate_box(_box_path text,
						  _reset    boolean DEFAULT TRUE)
RETURNS text AS $BODY$
DECLARE
   rec record;
BEGIN

 	IF (_reset) THEN
	        RAISE NOTICE 'Deleting %', _box_path;
 		PERFORM sqlite_fs.remove(_box_path); -- maybe better just truncate
 	END IF;

 	--create box
	RAISE NOTICE 'Creating is %', _box_path;
 	PERFORM sqlite_fs.make(_box_path, umask => 0o000); -- everybody can read and write. Ok for our testing

	--Create dbox content entries and files' info
	RAISE NOTICE 'Inserting entries';
	FOR rec IN (
		SELECT f.inode AS ino,
		       f.name AS display_name,
		       EXTRACT(EPOCH FROM f.created_at)::bigint AS ctime, -- loose precision
		       EXTRACT(EPOCH FROM f.modified_at)::bigint AS mtime,
		       1::bigint AS nlink,
		       f.is_dir,
		       f.parent_inode AS parent_ino,
		       f.size AS size,
		       q.mountpoint AS mountpoint,
		       q.rel_path AS rel_path,
		       q.prepend AS prepend,
		       q.append AS append,
		       q.payload_size AS payload_size
		FROM public.entries f
		LEFT JOIN public.files q ON q.inode = f.inode
	)
	LOOP

	  -- RAISE NOTICE 'Handling %: %', rec.ino, rec.display_name;
	  -- insert entries
          PERFORM sqlite_fs.insert_entry(_box_path,
					rec.ino, rec.display_name, rec.parent_ino,
				        rec.ctime,
				        rec.mtime,
				      	rec.nlink,
					rec.size,
				      	rec.is_dir);

	  -- insert files (if not is_dir)
	  CONTINUE WHEN rec.is_dir;

 	  PERFORM sqlite_fs.insert_file(_box_path, rec.ino,
	                             	rec.mountpoint, rec.rel_path,
					null, rec.payload_size, rec.prepend, rec.append);

	  -- Adding the file Accession ID (for example)
	  PERFORM sqlite_fs.insert_attribute(_box_path, rec.ino,
			                     'user.accession_id',
					     'FS-' || rec.ino::text);


	
    	END LOOP;

	RETURN 'OK';
END;
$BODY$
LANGUAGE plpgsql;
