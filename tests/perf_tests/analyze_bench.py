import json
import sys

import numpy as np
import matplotlib.pyplot as plt

def plotBenchGraph(name, x, y):
    list = name.split('_')[1:-1]
    newName = ' '.join(list)

    plt.figure(figsize=(11.7,8.3))
    plt.grid(which='both')
    plt.grid(which='minor', alpha=0.2)
    plt.grid(which='major', alpha=0.5)
    plt.title(newName + ', time dependency on size')
    plt.minorticks_on()
    plt.autoscale()
    plt.xlabel("size, bytes", fontsize=10)
    plt.ylabel("time, ns", fontsize=10)
    plt.plot(x, y, 'bo')
    plt.plot(x, y, 'r--')
    plt.savefig(name + '.png')

def main():
    # List all benchmarks here
    benchmarkNames = ['BM_AES128_Encrypt_RandomData', 'BM_AES128_Decrypt_RandomData', 'BM_RSA_Encrypt_RandomData', 'BM_RSA_Decrypt_RandomData',
        'BM_DoubleEncryptor_Encrypt_RandomData', 'BM_DoubleEncryptor_Decrypt_RandomData']

    if len(sys.argv) != 2:
        print('Error! No input file provided, usage: python analyze_bench.py <input_bench_json>')
        exit(-1)
    
    print('Input JSON file is ' + sys.argv[1])
    with open(sys.argv[1]) as f:
        fileData = f.read()

    dictData = json.loads(fileData)
    print('Successfuly read JSON data!')

    for benchName in benchmarkNames:        
        print('Current benchmark: ' + benchName)

        benchCPUtime = np.array([])
        benchSizes = np.array([])

        for bench in dictData['benchmarks']:
            # We need only current bench, bench time is only in iterations
            if (bench['run_type'] != 'iteration' or benchName not in bench['name']):
                continue
            
            benchCPUtime = np.append(benchCPUtime, bench['cpu_time'])
            # Extract argument
            benchSizes = np.append(benchSizes, int(bench['name'].replace(benchName + '/', '')))

        # Plot bench data
        plotBenchGraph(benchName, benchSizes, benchCPUtime)

        print('Benchmark CPU time array:')
        print(benchCPUtime)

        print('Benchmark iteration values array:')
        print(benchSizes)

if __name__ == '__main__':
    main()