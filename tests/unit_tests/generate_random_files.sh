#!/bin/bash

sizes=( "32MB" "128MB" "256MB" "512MB" "1GB" "2GB" )

for size in "${sizes[@]}"
do
    fileName="test_file_${size}.dat"
    echo "Generating ${fileName}"
    dd if=/dev/random of=${fileName}  bs=${size}  count=1
done

echo "Test files have been generated"
