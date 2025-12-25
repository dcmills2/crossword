#!/bin/bash
for f in `cat unencrypted/encrypt_list.txt`; do
  for f2 in `ls unencrypted/$f`; do
    python ./do_encrypt_file.py "unencrypted/key.bin" "$f2"
    # Remove the first 2 directory components
    dest="${f2#*/*/}"
    dest_dir=$(dirname "$dest")
    mkdir -p "encrypted/html/$dest_dir"
    mv "$f2.encrypted" "encrypted/html/${dest}.encrypted"
  done
done
