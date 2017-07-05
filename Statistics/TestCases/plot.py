
#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import xlrd
import numpy as np
import matplotlib.pyplot as plt
import csv as csv
import pandas as pd
from pandas import DataFrame 
from numpy import array

	
import sys
import numpy as np
import matplotlib.pyplot as plt
import csv as csv
import pandas as pd
from pandas import DataFrame
from matplotlib import cm as cm	
from matplotlib.pylab import *
from matplotlib.patches import Ellipse
#----------------------------------------------------------------------

stIndex = 11

def createFrange(X):
	minVal = min(X).astype(np.float)
	maxVal = max(X).astype(np.float)
	i = minVal
	range = [0.0]
	step = (maxVal - minVal)/10.0
	while(i <= maxVal + step):
		range.append(i)
		i += step
	return range

    
def showHistogram(X, strX):
	plt.xlabel(strX)
	plt.ylabel("Frequency")
	plt.title(strX + " Histogram")
	bins = createFrange(X)
	plt.xticks(bins)
	plt.hist(X,bins,histtype='bar',rwidth=0.8)
	plt.show()

f = []
f1 = open('client_latency.csv','w')
f2 = open('client_cpu.csv','w')
f3 = open('server_latency.csv','w')
f4 = open('server_cpu.csv','w')
f.append(f1)
f.append(f2)
f.append(f3)
f.append(f4)


def open_file(path):
	"""
	Open and read an Excel file
	"""
	book = xlrd.open_workbook(path)
 
    	# print number of sheets
	print book.nsheets
 
	# print sheet names
	print book.sheet_names()
 
	# get the first worksheet
	first_sheet = book.sheet_by_index(0)
 
	# read a row
	#print first_sheet.row_values(0)
 
	# read a cell
	#cell = first_sheet.cell(0,0)
	#print cell
	#print cell.value
 
	# read a row slice
	#print first_sheet.row_slice(rowx=0,start_colx=0,end_colx=2)
	
	#no. of sheets in the excel
	n = book.nsheets
	
	for i in xrange(0,n):
		sheet_name = book.sheet_names()[i]
		print sheet_name
		cur_sheet = book.sheet_by_index(i)
		m = cur_sheet.row_values(0)
		f[i].write('cipher,mean,St Dev, median,90th Pct,max,min')
		f[i].write('\n')
		for j in xrange(0,len(m)):
			val =  cur_sheet.col_values(j,stIndex)	
			X1 = array(val)
			#print X1
			mean_X1 = np.mean(X1)
			var_X1 = np.std(X1)
			median_X1 = np.median(X1)
			percentile = np.percentile(X1, 90)
			counts = np.bincount(np.int32(X1))
			
			print np.argmax(counts)
			print counts
			print np.max(X1)
			print np.min(X1)
			print mean_X1
			print var_X1
			print  median_X1
			print percentile
			#showHistogram(X1, "X1")
			f[i].write(str(m[j]));f[i].write(',')
			f[i].write(str(mean_X1));f[i].write(',')
			f[i].write(str(var_X1)); f[i].write(',')
			f[i].write(str(median_X1)); f[i].write(',')
			f[i].write(str(percentile)); f[i].write(',')
			f[i].write(str(np.max(X1)));f[i].write(',')
			f[i].write(str(np.min(X1)));
			f[i].write('\n')
		f[i].close()
			


def plotType(plotNum,str):
	if plotNum == 0:
			title(str + "\n" + "Handshake Latency")
			xlabel(" Time (us) ")
	elif plotNum == 1:
			title(str + "\n" + "CPU Usage")
			xlabel(" Time (us) ")

		

def plots(testCase):
	
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
	
	
	
	
	# Fonts
	rcParams['font.family'] = "sans-serif"
	rcParams['font.sans-serif'] = ["Droid Sans"]
	rcParams['font.size'] = 11
	
	# Create figure
	fig = figure(num=None, figsize=(5.51, 7.79), dpi=100)
	ax = fig.add_subplot(111)
	
	if plotNum == 0:
		color1 = '#F4C842'
		color2 = '#BD1550'
	else:
		color1 = '#77A3EA'
		color2 = '#D3C994'

	# Bar plot
	pos = (np.arange(len(data))+0.5)[::-1]
	client = barh(pos + 0.4, [float(x[1]) for x in data],
			  color=color1,
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
			  color=color2,
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
	
	# Axis and legend
	yticks(pos + 0.4, [x[0].replace(" ","\n",1) for x in data])
	
	
		
	
	if testCase == 0:
		plotType(plotNum,"TLS1_2_No_Resumption");
	elif testCase == 1:
		plotType(plotNum,"TLS1_2_Session_Ids");
	elif testCase == 2:
		plotType(plotNum,"TLS1_2_Session_Tickets")
	elif testCase == 3:
		plotType(plotNum,"TLS1_3_No_Resumption");
	elif testCase == 4:
		plotType(plotNum,"TLS1_3_Shared_PSK");
	elif testCase == 5:
		plotType(plotNum,"TLS1_3_External_PSK");
	elif testCase == 6:
		plotType(plotNum,"TLS1_2_No_Resumption");
	elif testCase == 7:
		plotType(plotNum,"TLS1_3_No_Resumption");
	else:
		plotType(plotNum,"");
	   
	legend(['Client','Server'], prop=dict(size=11),
	   fancybox=True, shadow=True)
	
	
	show()



#----------------------------------------------------------------------
if __name__ == "__main__":
	paths = ["TLS1_2_NoResumption.xlsx","TLS1_2_Session_Ids.xlsx","TLS1_2_Session_Tickets.xlsx","TLS1_3_NoResumption.xlsx","TLS1_3_PSK.xlsx","TLS1_3_Ext_PSK.xlsx","Spl_1.xlsx","Spl_2.xlsx"]
	print(" Test cases \n"
      	"0. TLS1_2 No Resumption\n"
      	"1. TLS1_2 Resumption Using Session Ids\n"
      	"2. TLS1_2 Resumption Using Session Tickets\n"
      	"3. TLS1_3 No Resumption\n"
      	"4. TLS1_3 Resumption using Shared key\n"
	"5. TLS1_3 Resumption External PSK")
	
	testCase = input("Enter your choice here: ")
	open_file(paths[testCase])
	plots(testCase)



