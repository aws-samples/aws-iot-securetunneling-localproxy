#!/bin/bash

echo This script is deprecated, please refer to the Docker Images section of the README for the recommended method of pulling and running images from ECR.

while getopts p: flag; do
  case "${flag}" in
    p) port=${OPTARG} ;;
  esac
done

if [ -z $port ]; then
  docker run --name localproxy --rm -it aws-iot-securetunneling-localproxy:latest bash
else
  echo Running the container with exposed port: $port
  docker run --name localproxy --expose=$port -p $port:$port --rm -it aws-iot-securetunneling-localproxy:latest bash
fi
