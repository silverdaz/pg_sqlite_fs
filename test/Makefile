SHELL := /bin/bash

all: latest

build: ARGS+=--target BUILD
build latest:
	cd .. && docker build $(ARGS) -t pg_sqlite_fs:$@ -f test/Dockerfile .

SQLITE_NAME=test-box.sqlite
SQLITE_DIR=/tmp/sqlite-boxes
SQLITE=$(SQLITE_DIR)/$(SQLITE_NAME)

$(SQLITE_DIR):
	mkdir $@
	chmod o+rwx $@

up: | $(SQLITE_DIR)
	docker run -d --rm --name pg-test \
	           -v $(SQLITE_DIR):/data/sqlite-boxes \
	           -e POSTGRES_PASSWORD=supersecret \
	       pg_sqlite_fs:latest

down:
	docker stop pg-test

exec:
	docker exec -it pg-test bash

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
	sqlite3 $< "UPDATE files SET mountpoint = '$(shell pwd)'"

.PHONY:mnt
mnt: $(SQLITE)
	/home/daz/Workspace/crypt4gh-sqlite/crypt4gh-sqlite.fs -f -o local_debug=3,ro,default_permissions,allow_root $< $@


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

exports:
	mkdir $@
exports/entries.txt: $(SQLITE) | exports
	sqlite3 $< 'SELECT inode, name, parent_inode, is_dir, size, nlink FROM entries' > $@
exports/files.txt: $(SQLITE) | exports
	sqlite3 $< 'SELECT inode, mountpoint, rel_path, prepend, append FROM files' > $@
exports/xattr.txt: $(SQLITE) | exports
	sqlite3 $< 'SELECT * FROM extended_attributes' > $@
export-all: exports/entries.txt exports/files.txt exports/xattr.txt


clean:
	rm -rf $(SQLITE_DIR)
distclean: clean
	rm -rf exports
