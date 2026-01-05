INSERT INTO public.entries(inode, name, parent_inode)
VALUES (2, 'dir1', 1),
       (3, 'dir2', 1)
ON CONFLICT DO NOTHING;

INSERT INTO public.entries(inode, name, parent_inode)
VALUES (22, 'subdir1', 2),
       (33, 'subdir2', 3)
ON CONFLICT DO NOTHING;

INSERT INTO public.entries(inode, name, parent_inode, is_dir)
VALUES (222, 'my-file1.txt', 22, false),
       (333, 'my-file2.txt', 33, false)
ON CONFLICT DO NOTHING;

INSERT INTO public.files(inode, mountpoint, rel_path, payload_size, prepend, append)
VALUES (222, '/path/to', 'file1.txt', 6, E'==== header 1 ====\n'::bytea, null),
       (333, '/other/path/to', 'file2.txt', 8, null, E'\n==== footer 2 ===='::bytea)
ON CONFLICT(inode) DO UPDATE SET mountpoint = excluded.mountpoint,
                                 rel_path = excluded.rel_path,
                          	 payload_size = excluded.payload_size,
                          	 prepend = excluded.prepend,
                          	 append = excluded.append
                          	 ;

UPDATE public.entries SET size = payload_size + COALESCE(length(prepend), 0) + COALESCE(length(append), 0)
FROM public.files
WHERE entries.inode = files.inode
;
