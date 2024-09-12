FROM ubuntu

ADD daemon /usr/bin/daemon
ADD daemon.bpf.o /usr/bin/daemon.bpf.o

ENTRYPOINT ["daemon"]
