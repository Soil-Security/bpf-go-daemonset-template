FROM alpine:3

ADD daemon /root/
ADD daemon.bpf.o /root

ENTRYPOINT ["/root/daemon"]
