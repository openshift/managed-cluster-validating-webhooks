#!/bin/bash

# AppSRE team CD

set -exv

# TODO: Invoke this make target directly from appsre ci-int and scrap this file
make -C $(dirname $0)/../ build-push
