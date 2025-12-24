#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <encryption_key>"
    exit 1
fi
for f in `cat unencrypted/encrypt_list.txt`; do
    ./do_encrypt_file.py "$1" "unencrypted/$f"
    dest=${f#*/} # Remove the first directory component
    dest_dir=$(dirname "$dest")
    mkdir -p "encrypted_html/$dest_dir"
    mv "unencrypted/$f.encrypted" "encrypted_html/${dest}.encrypted"
done
