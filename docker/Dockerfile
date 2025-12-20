FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y bind9 bind9utils dnsutils

COPY named.conf /etc/bind/named.conf
COPY rndc.key /etc/bind/rndc.key

EXPOSE 953

CMD ["named", "-g", "-c", "/etc/bind/named.conf"]