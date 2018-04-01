FROM ubuntu:14.04

Maintainer Harsha Bellur

RUN apt-get update
RUN apt-get -y install curl
RUN apt-get -y install git

# Install Stable Go
WORKDIR /opt
RUN curl -O https://storage.googleapis.com/golang/go1.10.1.linux-amd64.tar.gz && tar -C /usr/local -xzf /opt/go1.10.1.linux-amd64.tar.gz
ENV PATH /usr/local/go/bin:/usr/local/bin:$PATH
ENV GOPATH /usr/local/notification_manager
ENV GOBIN $GOPATH/bin

# SSH key for github account
# The expectation is that the directory which has the "Dockerfile" must also contain
# a directory named "keys" which contains the SSH key file for the github account
COPY keys/id_rsa /root/.ssh/id_rsa
RUN chmod 700 /root/.ssh/id_rsa && echo "Host github.com\n\tStrictHostKeyChecking no\n" >> /root/.ssh/config

# Install vesper
WORKDIR /usr/local
#RUN git clone git@github.com:iris-platform/vesper.git
RUN git clone -b v2.0 git@github.com:iris-platform/vesper.git
RUN rm -rf /usr/local/vesper/.git
RUN go install vesper
