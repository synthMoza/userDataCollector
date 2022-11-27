#!/bin/bash

./measure > res_udc.txt
./measure_gpg.sh > res_gpg.txt
python3 analyze_measure.py res_gpg.txt res_udc.txt
