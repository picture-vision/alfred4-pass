#!/bin/bash

set -e

QUERY=$1
PATH=/opt/homebrew/bin:$PATH

pass generate "$QUERY" -n 20 -c 
