# Statistics <br />
Statistics Directory contains generated client Server Logs and TestCases Directory <br />

## TestCases Directory <br />
TestCases Directory contains excel worksheets with Latency and CPU usage statistics for the following test cases performed <br />
1) TLS1.2 No rsesumption
2) TLS 1.2 Resumption with Session Identifers
3) TLS 1.2 Resumption with Session Tickets
4) TLS 1.3 No Resumption
5) TLS 1.3 Resumption with Shared PSK
6) TLS 1.3 with External PSK
7) TLS 1.2 No resumption on machines with ping time 120 ms
8) TLS 1.3 No resumptions on machines with ping time 120 ms

The plots for Latency and CPU utilization can be generated using the python script plot.py in Statitics/TestCases. <br />

#### Example Run:

$ python plot.py

$Test cases 

  0. TLS1_2 No Resumption
  1. TLS1_2 Resumption Using Session Ids
  2. TLS1_2 Resumption Using Session Tickets
  3. TLS1_3 No Resumption
  4. TLS1_3 Resumption using Shared key
  5. TLS1_3 Resumption External PSK
  Enter your choice here for testCase Number: 0
  
$ 0. Latency

  1. CPU Usage
  
  Enter your choice here for plot type: 0
  
  
  
  
