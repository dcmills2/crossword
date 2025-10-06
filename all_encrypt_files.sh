#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <encryption_key>"
    exit 1
fi
for f in `ls unencrypted`; do
    ./do_encrypt_file.py $1 unencrypted/$f
done
mv unencrypted/*.encrypted encrypted_html/
