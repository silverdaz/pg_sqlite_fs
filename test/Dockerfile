##########################
## Build env
##########################

FROM postgres:18 AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update; \
#    apt-get upgrade -y; \
    apt-get install -y --no-install-recommends \
	    ca-certificates pkg-config git gcc make automake autoconf libtool \
            libedit-dev libpq-dev postgresql-server-dev-18

######### SQLite box pgxs
COPY . /var/src/pg_sqlite_fs

WORKDIR /var/src/pg_sqlite_fs
RUN make
RUN make install

############ For debug
RUN echo "alias ll='ls -al'" >> ~/.bashrc
RUN ldconfig -v

##########################
## Final image
##########################

FROM postgres:18

LABEL maintainer="Frédéric Haziza <silverdaz@gmail.com>"

COPY --from=BUILD /usr/lib/postgresql/18                  /usr/lib/postgresql/18
COPY --from=BUILD /usr/share/postgresql/18                /usr/share/postgresql/18

RUN ldconfig -v

# We are the root user
RUN echo "umask 000" > ~/.bashrc
