#!/bin/bash
bash ./fetch-and-decrypt-puzzle.sh
TODAY=$(date +%F)
git add encrypted/html/mini.json.encrypted encrypted/html/puzzles/$TODAY.json.encrypted
git commit -m "add $TODAY"
git push
