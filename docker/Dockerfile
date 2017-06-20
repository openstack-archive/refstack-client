FROM ubuntu:16.04

RUN apt-get update && \
    apt-get install -y sudo curl vim less tar

ARG UID
ARG GID
ENV DEV_USER=ubuntu COLUMNS=120

RUN [ ! $(grep ":${GID}:" /etc/group) ] && groupadd -g  ${GID:-1000} ${DEV_USER}

RUN useradd -g ${DEV_USER} -u ${UID:-1000} -s /bin/bash -d /home/${DEV_USER} -m ${DEV_USER} && \
    ( umask 226 && echo "${DEV_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/50_${DEV_USER} )

USER ${DEV_USER}
WORKDIR /home/${DEV_USER}

