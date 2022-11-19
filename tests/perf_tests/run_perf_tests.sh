#!/bin/bash

./perf_tests --benchmark_format=json > output.json
python3 analyze_bench.py output.json
