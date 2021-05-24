#!/bin/bash

while getopts p: flag
do
    case "${flag}" in
        p) port=${OPTARG};;
    esac
done

if [ -z $port ]; then
	docker run --name localproxy --rm -it aws-iot-securetunneling-localproxy:latest bash;
else
	echo Running the container with exposed port: $port
	docker run --name localproxy --expose=$port -p $port:$port --rm -it aws-iot-securetunneling-localproxy:latest bash;
fi

