#!/bin/bash
for f in `cat unencrypted/encrypt_list.txt`; do
    ./do_encrypt_file.py "unencrypted/key.bin" "unencrypted/$f"
    dest=${f#*/} # Remove the first directory component
    dest_dir=$(dirname "$dest")
    mkdir -p "encrypted/html/$dest_dir"
    mv "unencrypted/$f.encrypted" "encrypted/html/${dest}.encrypted"
done
