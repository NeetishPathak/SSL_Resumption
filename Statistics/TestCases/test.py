import xlrd
import numpy as np
import matplotlib.pyplot as plt
import csv as csv
import pandas as pd
from pandas import DataFrame 
from numpy import array
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
			

			


#----------------------------------------------------------------------
if __name__ == "__main__":
	paths = ["TLS1_2_NoResumption.xlsx","TLS1_2_Session_Ids.xlsx","TLS1_2_Session_Tickets.xlsx","TLS1_3_NoResumption.xlsx","TLS1_3_PSK.xlsx","Spl_1.xlsx","Spl_2.xlsx"]
	print(" Test cases \n"
      	"0. TLS1_2 No Resumption\n"
      	"1. TLS1_2 Resumption Using Session Ids\n"
      	"2. TLS1_2 Resumption Using Session Tickets\n"
      	"3. TLS1_3 No Resumption\n"
      	"4. TLS1_3 Resumption using Shared key")
	
	testCase = input("Enter your choice here: ")
	open_file(paths[testCase])



