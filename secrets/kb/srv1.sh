#!/bin/bash


REJESTR=registry.<example.com>

docker build -t py3a .
docker image tag py3a:latest $REJESTR/py3a:latest
docker push $REJESTR/py3a:latest