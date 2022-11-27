#!/bin/bash

TIMEFORMAT=%R

sizes=( "32MB" "128MB" "256MB" "512MB" "1GB" "2GB" )
recipient=RustyOnion

echo "Measuring encrypting time using GPG"
for size in "${sizes[@]}"
do
    fileName="test_file_${size}.dat"
    timeSec=$( { time gpg --cipher-algo AES256 --compress-algo none --recipient ${recipient} --encrypt ${fileName}; } 2>&1 )

    outputFileSize=$(stat -c%s "${fileName}.gpg")

    echo "File Name: ${fileName}, output size = ${outputFileSize} bytes, ellapsed time = ${timeSec} s"
done
