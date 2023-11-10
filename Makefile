# Makefile to build the pg_sqlite_fs extension

EXTENSION = pg_sqlite_fs

DATA_built = $(EXTENSION)--1.0.sql
DATA = $(wildcard $(EXTENSION)--*--*.sql)

# compilation configuration
MODULE_big = $(EXTENSION)
OBJS = $(patsubst %.c,%.o,$(wildcard src/*.c))

#PG_CFLAGS = -std=gnu18

PG_CPPFLAGS += -Isrc
SHLIB_LINK = -ldl -lpthread

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

$(EXTENSION)--1.0.sql: $(EXTENSION).sql
	cat $^ > $@
