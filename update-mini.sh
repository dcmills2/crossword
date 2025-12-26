#!/bin/bash
git pull origin master
bash ./fetch-and-encrypt-puzzle.sh
TODAY=$(date +%F)
git add encrypted/html/mini.json.encrypted encrypted/html/puzzles/$TODAY.json.encrypted
git commit -m "add $TODAY"
git push origin master
