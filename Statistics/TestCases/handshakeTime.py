#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import sys
import numpy as np
import matplotlib.pyplot as plt
import csv as csv
import pandas as pd
from pandas import DataFrame
from matplotlib import cm as cm

print(" Test cases \n"
      "0. TLS1_2 No Resumption\n"
      "1. TLS1_2 Resumption Using Session Ids\n"
      "2. TLS1_2 Resumption Using Session Tickets\n"
      "3. TLS1_3 No Resumption\n"
      "4. TLS1_3 Resumption using Shared key")
	
testCase = input("Enter your choice here: ")

print(" Benchmarking Plots \n"
      "0. Latency\n"
      "1. CPU Usage")
plotNum = input("Enter your choice here: ")

data = []

#read the csv files fro latency
file_cl = open('client_latency.csv','rb')
file_object_cl = csv.reader(file_cl)

file_sl = open('server_latency.csv','rb')
file_object_sl = csv.reader(file_sl)

d1 = list(file_object_cl)
d2 = list(file_object_sl)
print d1 + d2
length = len(d1)

data1 = []
for x in xrange(1,length):
	print x
	d = d1[x] + d2[x]
	print d
	data1.append(d)


file_cc = open('client_cpu.csv','rb')
file_object_cc = csv.reader(file_cc)

file_sc = open('server_cpu.csv','rb')
file_object_sc = csv.reader(file_sc)

d1 = list(file_object_cc)
d2 = list(file_object_sc)
print d1 + d2
length = len(d1)

data2 = []
for x in xrange(1,length):
	print x
	d = d1[x] + d2[x]
	print d
	data2.append(d)

data.append(data1)
data.append(data2)

print data
'''
handshakes = 100
data = [
    # Set 0
    [
    ("RSA 1024",     2.092,   0.274, 1.900, 0.313),
    ("RSA 2048",     3.193,   0.276, 2.982, 0.316),
    ("RSA 4096",     9.556,  0.372, 9.386, 0.421),
    ("ECDSA",     13.2,  0.368, 13.033, 0.413)
    ],
    # Set 1
    [
    ("RSA 1024",     2.170,   0.346, 2.00, 0.384),
    ("RSA 2048",     3.203,   0.335, 3.057, 0.382),
    ("RSA 4096",     7.819,  0.341, 7.663, 0.379),
    ("ECDSA",     12.945,  0.270, 12.712, 0.305)
    ],
    # Set 2
    [
    ("RSA 1024",     0.843,   0.163, 0.978, 0.173),
    ("RSA 2048",     0.952,   0.163, 1.956, 0.170),
    ("RSA 4096",     1.095,  0.191, 8.165, 0.198),
    ("ECDSA",     6.767,  0.191, 6.161, 0.199)
    ],
    # Set 3
    [
    ("RSA 1024",     0.864,   0.167, 1.022, 0.183),
    ("RSA 2048",     0.893,   0.185, 2.007, 0.204),
    ("RSA 4096",     1.057,  0.163, 6.472, 0.184),
    ("ECDSA",     6.436,  0.154, 6.154, 0.175)
    ], 
    ]
'''
data = data[int(plotNum)]
#clientvsserver = [True, False]
#clientvsserver = clientvsserver[int(sys.argv[1])]


from matplotlib.pylab import *
from matplotlib.patches import Ellipse

# Fonts
rcParams['font.family'] = "sans-serif"
rcParams['font.sans-serif'] = ["Droid Sans"]
rcParams['font.size'] = 11

# Create figure
fig = figure(num=None, figsize=(5.51, 7.79), dpi=100)
ax = fig.add_subplot(111)

# Bar plot
pos = (np.arange(len(data))+0.5)[::-1]
client = barh(pos + 0.4, [float(x[1]) for x in data],
              color='#F4C842',
              height=0.4)
'''
client_res = barh(pos + 0.4, [float(x[8]) for x in data],
              color='#77A3EA',
              height=0.4)

server = barh(pos, [x[3] for x in data],
              color='#BD1550',
              height=0.4)
'''
server_res = barh(pos, [float(x[8]) for x in data],
              color='#BD1550',
              height=0.4)


# Write value inside bars
for rect in client + server_res:# + server + server_res:
    width = rect.get_width()
    if width > 3:
        xloc = width - 0.3
        color = 'white'
        align = 'right'
    else:
        xloc = width + 0.3
        color = 'black'
        align = 'left'
    yloc = rect.get_y() + rect.get_height()/2.0
    text(xloc, yloc, "%.2f" % width,
         horizontalalignment=align,
         verticalalignment='center',
         color=color, weight='bold')
'''
# Write ratio
for i in range(len(data)):
    if not clientvsserver and i == 0:
        continue
    width = server[i].get_width()
    if width > 3:
        xloc = width + 4
    else:
        xloc = width + 0.4*len(data) + 2.6
    yloc = server[i].get_y() + server[i].get_height()/2.0
    if clientvsserver:
        ratio = data[i][2]/data[i][1]
    else:
        ratio = data[i][2]/data[0][2]
    if ratio <= 2:
        ratio = "%+d %%" % (ratio*100-100)
    else:
        ratio = u"× %.1f" % ratio
    el = Ellipse((xloc, yloc), len(data)*0.4 + 1.6, len(data)*0.04 + 0.16, edgecolor="white",
                 facecolor="#8A9B0F", alpha=0.9)
    ax.add_artist(el)
    text(xloc, yloc, ratio,
         horizontalalignment="center",
         verticalalignment='center',
         color="white", weight='bold')
'''
# Axis and legend
yticks(pos + 0.4, [x[0].replace(" ","\n",1) for x in data])


def plotType(str):
	if plotNum == 0:
    		title(str + "\n" + "Handshake Latency")
    		xlabel(" Time (us) ")
	elif plotNum == 1:
    		title(str + "\n" + "CPU Usage")
    		xlabel(" Time (us) ")


if testCase == 0:
	plotType("TLS1_2_No_Resumption");
elif testCase == 1:
	plotType("TLS1_2_Session_Ids");
elif testCase == 2:
	plotType("TLS1_2_Session_Tickets")
elif testCase == 3:
	plotType("TLS1_3_No_Resumption");
elif testCase == 4:
	plotType("TLS1_3_Shared_PSK");
else:
	plotType("");

'''
if plotNum == 0:
    title("Handshake Latency")
    xlabel(" Time (us) ")
elif plotNum == 1:
    title("CPU Usage")
    xlabel(" Time (us) ")
elif plotNum == 2:
    title("CPU Usage per sec (Without Session Tickets)")
    xlabel(" Time (ms) ")
else:
    title("CPU Usage per sec (With Session Tickets)")
    xlabel(" Time (ms) ")
'''
       
legend(['Client','Server'], prop=dict(size=11),
       fancybox=True, shadow=True)


show()
