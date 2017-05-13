#!/bin/sh
rsync -rave "ssh -p 22"  ./ refone@ryzen:~/destdir
