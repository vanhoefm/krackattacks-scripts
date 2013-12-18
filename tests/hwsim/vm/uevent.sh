#!/bin/sh

# assume this was a call for CRDA,
# if not then it won't find a COUNTRY
# environment variable and exit
exec crda
