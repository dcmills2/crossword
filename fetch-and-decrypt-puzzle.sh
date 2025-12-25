#!/bin/bash
# today's date (yyyy-mm-dd)
TODAY=$(date +%F)
if [[ $# -ne 1 ]]; then
  filename="mini.json"
  ./unencrypted/**/get-todays-mini.sh
else
  filename="puzzles/$1.json"
  ./unencrypted/**/fetch-puzzle.sh $1
fi
filepath="`echo unencrypted/**/$filename`"
echo $filepath
./do_encrypt_file.py "unencrypted/key.bin" "$filepath"
mv "$filepath.encrypted" "encrypted/html/$filename.encrypted"
if [[ $# -ne 1 ]]; then
  puzzlesDir="`echo unencrypted/**/puzzles`"
  cp "$filepath" "$puzzlesDir/$TODAY.json"
  cp "encrypted/html/$filename.encrypted" "encrypted/html/puzzles/$TODAY.json.encrypted"
fi
