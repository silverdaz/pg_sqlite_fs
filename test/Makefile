SHELL := /bin/bash

all: latest

build: ARGS+=--target BUILD
build latest:
	cd .. && docker build $(ARGS) -t pg_sqlite_fs:$@ -f test/Dockerfile .

SQLITE_NAME=test-box.sqlite
SQLITE_DIR=/mnt/sqlite-boxes
SQLITE=$(SQLITE_DIR)/$(SQLITE_NAME)

$(SQLITE_DIR):
	sudo mkdir -p -m 777 $@

up: | $(SQLITE_DIR)
	docker run -d --rm --name pg-test \
	           -v $(SQLITE_DIR):/data/sqlite-boxes \
	           -e POSTGRES_PASSWORD=supersecret \
	       pg_sqlite_fs:latest

down:
	docker stop pg-test

exec:
	docker exec -it pg-test bash

logs:
	docker logs -f pg-test

wait:
	@sleep 3

PSQL_T=docker exec -it pg-test psql -h localhost -U postgres
PSQL=docker exec -i pg-test psql -h localhost -U postgres
psql:
	$(PSQL_T)

insert init:
	$(PSQL) < $@.sql 

$(SQLITE):
	$(PSQL) <<<"SELECT * FROM sqlite_fs.generate_box(concat_ws('/', current_setting('sqlite_fs.location'), '$(SQLITE_NAME)'));"

gen: $(SQLITE)

adjust: $(SQLITE)
	sudo chmod 666 $<
	sqlite3 $< "UPDATE files SET mountpoint = '$(shell pwd)'"



output.entries.txt: $(SQLITE)
	sqlite3 $< 'SELECT inode, name, parent_inode, is_dir, size, nlink FROM entries' > $@
output.files.txt: $(SQLITE)
	sqlite3 $< 'SELECT inode, mountpoint, rel_path, prepend, append FROM files' > $@
output.xattr.txt: $(SQLITE)
	sqlite3 $< 'SELECT * FROM extended_attributes' > $@

.INTERMEDIATE: output.entries.txt output.files.txt output.xattr.txt

compare-%: output.%.txt
	diff output.$*.txt exports/$*.txt
compare: compare-entries compare-files compare-xattr

# exports:
# 	mkdir $@
# exports/entries.txt: $(SQLITE) | exports
# 	sqlite3 $< 'SELECT inode, name, parent_inode, is_dir, size, nlink FROM entries' > $@
# exports/files.txt: $(SQLITE) | exports
# 	sqlite3 $< 'SELECT inode, mountpoint, rel_path, prepend, append FROM files' > $@
# exports/xattr.txt: $(SQLITE) | exports
# 	sqlite3 $< 'SELECT * FROM extended_attributes' > $@
# export-all: exports/entries.txt exports/files.txt exports/xattr.txt


clean:
	rm -rf $(SQLITE_DIR)


.PHONY:mount unmount
$(SQLITE_DIR)/mnt:
	mkdir -m 700 $@
mount: $(SQLITE) | $(SQLITE_DIR)/mnt
	crypt4gh-sqlite.fs -o ro,default_permissions,allow_root $< $|
unmount:
	umount $(SQLITE_DIR)/mnt

check:
	diff $(SQLITE_DIR)/mnt/dir1/subdir1/my-file1.txt exports/full-file1.txt
	diff $(SQLITE_DIR)/mnt/dir2/subdir2/my-file2.txt exports/full-file2.txt
