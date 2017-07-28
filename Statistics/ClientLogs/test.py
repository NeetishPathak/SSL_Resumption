
#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
plot.py file takes an excel file with four sheets
viz. Latency_C, CPU_C, Latency_S, CPU_S
and find the performance statistics
'''

import numpy as np

import csv as csv
 
from numpy import array	
import sys
import numpy as np


def findStats(filename):
	file_c1 = open(filename,'rb')
	f = csv.reader(file_c1)
	lst = list(f)
	#print lst
	con_lat = []
	con_cpu_u = []
	con_cpu_s = []
	
	rw_lat = []
	rw_cpu_u = []
	rw_cpu_s = []
	count = 0;
	for x in lst:
		if count < 10:
			count += 1;
			continue;
		else:
			con_lat.append(int(x[0]));con_cpu_u.append(int(x[2]));con_cpu_s.append(int(x[3]));
			rw_lat.append(int(x[4]));rw_cpu_u.append(int(x[6]));rw_cpu_s.append(int(x[7]));
			count += 1
		if(count >= 1000):
			break;
	d1 = array(con_lat);d2 = array(con_cpu_u);d3 = array(con_cpu_s);
	d4 = array(rw_lat); d5 = array(rw_cpu_u); d6 = array(rw_cpu_s);
	print str("Mean "), np.mean(d1), np.mean(d2), np.mean(d3), np.mean(d4), np.mean(d5), np.mean(d6)
	print str("95 % "), np.percentile(d1,95), np.percentile(d2,95), np.percentile(d3,95), np.percentile(d4,95), np.percentile(d5,95), np.percentile(d6,95)
	print str("99 % "), np.percentile(d1,99), np.percentile(d2,99), np.percentile(d3,99), np.percentile(d4,99), np.percentile(d5,99), np.percentile(d6,99)
	print str("Stdv "), np.std(d1),np.std(d2),np.std(d3),np.std(d4),np.std(d5),np.std(d6)
	print str("Min  "), np.min(d1), np.min(d2),np.min(d3), np.min(d4),np.min(d5), np.min(d6); 
	print str("Max  "), np.max(d1), np.max(d2),np.max(d3), np.max(d4),np.max(d5), np.max(d6); 
	print str("Median "), np.median(d1), np.median(d2),np.median(d3), np.median(d4),np.median(d5), np.median(d6);
	
	
#Main function
#----------------------------------------------------------------------
if __name__ == "__main__":
	filename = str(sys.argv[1])
	findStats(filename)