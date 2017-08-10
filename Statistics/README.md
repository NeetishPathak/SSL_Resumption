# Statistics <br />
Statistics Directory contains generated client Server Logs and TestCases Directory <br />
The excel files will contain values for Connection and Complete Read/Write Operation Measured on corresponding machines. For client logs, check Statistics/ClientLogs directory. For server logs, check Statistics/ServerLogs directory <br/>

The first four values in each row of the csv files correspond to just the connection (TCP + SSL connect) (C)<br/>
The next four values correspond to complete write/read operation after connection (W/R)<br/>
So the order in which the file data is to be read is <br/>

Latency (C), CPU Usage (C), User CPU Usage (C), System CPU Usage (C), Latency (W/R), CPU Usage (W/R), User CPU Usage (W/R), System CPU Usage (W/R) <br/>

To get the statistical paramters, run the python script called test.py <br/>
e.g. python test.py 2_1_TS_Client.csv <br/>
FileName Statistics/ClientLogs/2_1_TS_Client.csv<br/>

![Statistics](https://github.com/NeetishPathak/SSL_Resumption/blob/master/Statistics/TestCases/Stats.png)

## TestCases Directory <br />
TestCases Directory contains excel worksheets with Latency and CPU usage statistics for the following test cases performed <br />

0) TLS1.2 No resumption
1) TLS 1.2 Resumption with Session Identifers
2) TLS 1.2 Resumption with Session Tickets
3) TLS 1.3 No Resumption
4) TLS 1.3 Resumption with Shared PSK
5) TLS 1.3 with External PSK
6) TLS1_3 Resumption External PSK Session File
7) TLS 1.2 No Resumption Far-off Machines (ping time 120 ms)
8) TLS 1.3 No Resumption Far-off Machines (ping time 120 ms)
9) TLS 1.2 Resumption Far-off Machines  (ping time 120 ms)
10) TLS 1.3 Resumption Far-off Machines (ping time 120 ms)

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
  
  
  
  
