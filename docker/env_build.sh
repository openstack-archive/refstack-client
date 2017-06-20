#!/bin/bash -x

if [ "$EUID" -eq 0 ]
  then echo "This script should not be runned with sudo!"
  exit
fi

docker ps &> /dev/null; (( $? != 0 )) && echo 'Docker should be accessible without sudo '


CONTAINER_NAME=refstack_client

if [ $( docker ps -a -q --filter name=${CONTAINER_NAME} ) ]; then
    docker rm -f $( docker ps -a -q --filter name=${CONTAINER_NAME} )
fi

docker build -t ${CONTAINER_NAME} \
    --build-arg UID=$( id -u $USER ) \
    --build-arg GID=$( id -g $USER ) \
    --file $( git rev-parse --show-toplevel )/docker/Dockerfile \
    $( git rev-parse --show-toplevel )
