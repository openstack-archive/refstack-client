#!/bin/bash -x

if [ "$EUID" -eq 0 ]
  then echo "This script should not be runned with sudo!"
  exit
fi

docker ps &> /dev/null; (( $? != 0 )) && echo 'Docker should be accessible without sudo '

CONTAINER_NAME=refstack_client

if [ ! $( docker ps -q --filter name=${CONTAINER_NAME} ) ]; then
    ENV_CONTAINER=$( docker ps -a -q --filter name=${CONTAINER_NAME} )
    if [ ${ENV_CONTAINER} ]; then
        docker start -a -i $ENV_CONTAINER
        exit 0
    fi

    docker run \
        --dns=8.8.8.8 \
        -i -t \
        --name ${CONTAINER_NAME}\
        -v $( git rev-parse --show-toplevel ):/home/ubuntu/refstack-client \
        -e REFSTACK_CLIENT_TEMPEST_DIR=/home/ubuntu/tempest \
        ${CONTAINER_NAME} bash -c '~/refstack-client/setup_env -q && bash'
fi

ENV_CONTAINER=$( docker ps -q --filter name=${CONTAINER_NAME} )
[[ ! ${ENV_CONTAINER} ]] && exit 1

[[ $* ]] && {
    docker exec ${ENV_CONTAINER} $*
} || {
    docker exec -i -t ${ENV_CONTAINER} bash
}
