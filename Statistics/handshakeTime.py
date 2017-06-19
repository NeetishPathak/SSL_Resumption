#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import sys

print(" Benchmarking Plots \n"
      "0. Latency (without session tickets) \n"
      "1. Latency (with Session tickets) \n"
      "2. CPU Usage (without session tickets) \n" \
      "3. CPU Usage (with session tickets) ")
plotNum = input("Enter your choice here: ")

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
client = barh(pos + 0.4, [x[1] for x in data],
              color='#F4C842',
              height=0.4)
client_res = barh(pos + 0.4, [x[2] for x in data],
              color='#77A3EA',
              height=0.4)
server = barh(pos, [x[3] for x in data],
              color='#BD1550',
              height=0.4)
server_res = barh(pos, [x[4] for x in data],
              color='#D6BE9A',
              height=0.4)

# Write value inside bars
for rect in client + client_res + server + server_res:
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

if plotNum == 0:
    title("Handshake Latency (Without Session Tickets)")
    xlabel(" Time (ms) ")
elif plotNum == 1:
    title("Handshake Latency (With Session Tickets)")
    xlabel(" Time (ms) ")
elif plotNum == 2:
    title("CPU Usage per sec (Without Session Tickets)")
    xlabel(" Time (ms) ")
else:
    title("CPU Usage per sec (With Session Tickets)")
    xlabel(" Time (ms) ")
       
legend(['Client', 'Client_SR' , 'Server', 'Server_SR'], prop=dict(size=11),
       fancybox=True, shadow=True)


show()
