import json
import sys

import numpy as np
import matplotlib.pyplot as plt

def analyzeRes(lines1, lines2):
    inputSizes = np.array([32, 128, 256, 512, 1000, 2000])
    
    outputSizes1 = np.array([])
    times1 = np.array([])

    outputSizes2 = np.array([])
    times2 = np.array([])

    for i in range(1, len(lines1)):
        split1 = lines1[i].split(' ')
        split2 = lines2[i].split(' ')        

        outputSizes1 = np.append(outputSizes1, float(split1[6]))
        outputSizes2 = np.append(outputSizes2, float(split2[6]))

        times1 = np.append(times1, float(split1[-2]))
        times2 = np.append(times2, float(split2[-2]))
    
    plt.figure(figsize=(11.7,8.3))
    plt.grid(which='both')
    plt.grid(which='minor', alpha=0.2)
    plt.grid(which='major', alpha=0.5)
    plt.title('Compare UDC (our implementation) with GPG, encryption time')
    plt.minorticks_on()
    plt.autoscale()
    plt.xlabel("size, MB", fontsize=10)
    plt.ylabel("time, s", fontsize=10)

    plt.plot(inputSizes, times1, 'ro', label='GPG')
    plt.plot(inputSizes, times1, 'r--')

    plt.plot(inputSizes, times2, 'go', label='UDC')
    plt.plot(inputSizes, times2, 'g--')

    plt.legend()
    plt.savefig('encrypt_compare_time.png')

    plt.figure(figsize=(11.7,8.3))
    plt.grid(which='both')
    plt.grid(which='minor', alpha=0.2)
    plt.grid(which='major', alpha=0.5)
    plt.title('Compare UDC (our implementation) with GPG, encrypted file size diff with input file size')
    plt.minorticks_on()
    plt.autoscale()
    plt.xlabel("input file size, MB", fontsize=10)
    plt.ylabel("file sizes diff, bytes", fontsize=10)

    plt.plot(inputSizes, np.abs(outputSizes1 - inputSizes * 1e6), 'ro', label='GPG')
    plt.plot(inputSizes, np.abs(outputSizes1 - inputSizes * 1e6), 'r--')

    plt.plot(inputSizes, np.abs(outputSizes2 - inputSizes * 1e6), 'go', label='UDC')
    plt.plot(inputSizes, np.abs(outputSizes2 - inputSizes * 1e6), 'g--')

    plt.legend()
    plt.savefig('encrypt_compare_size.png')

def main():
    if len(sys.argv) != 3:
        print('Error! No input file provided, usage: python analyze_measure.py <res1> <res2>')
        exit(-1)
    
    res1 = sys.argv[1]
    res2 = sys.argv[2]

    with open(res1) as f:
        fileDataLines1 = f.readlines()
    with open(res2) as f:
        fileDataLines2 = f.readlines()

    analyzeRes(fileDataLines1, fileDataLines2)

if __name__ == '__main__':
    main()