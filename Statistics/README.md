# Statistics <br />
Statistics Directory contains generated client Server Logs and TestCases Directory <br />

## TestCases Directory <br />
TestCases Directory contains excel worksheets with Latency and CPU usage statistics for the following test cases performed <br />

0) TLS1.2 No rsesumption
1) TLS 1.2 Resumption with Session Identifers
2) TLS 1.2 Resumption with Session Tickets
3) TLS 1.3 No Resumption
4) TLS 1.3 Resumption with Shared PSK
5) TLS 1.3 with External PSK
6) TLS 1.2 No resumption on machines with ping time 120 ms
7) TLS 1.3 No resumptions on machines with ping time 120 ms

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
  6. TLS1_3 Resumption External PSK Session File
  7. TLS 1.2 No Resumption Far-off Machines 
  8. TLS 1.3 No Resumption Far-off Machines
  9. TLS 1.2 Resumption Far-off Machines 
  10. TLS 1.3 Resumption Far-off Machines 
  
  Enter your choice here for testCase Number: 0
  
$ 0. Latency

  1. CPU Usage
  
   Enter your choice here for plot type: 0
   
   ![Latency Test case 0](https://github.com/NeetishPathak/SSL_Resumption/blob/master/Statistics/TestCases/C0_L.png)
   ![CPU Usage Test case 0](https://github.com/NeetishPathak/SSL_Resumption/blob/master/Statistics/TestCases/C0_C.png)
  
  
  
  
