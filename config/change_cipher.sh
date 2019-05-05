#!/bin/bash

sed -i -e "s/\(.*\"method\": \"\)\(.*\)\(\".*\)/\1$1\3/g" client.json server.json
