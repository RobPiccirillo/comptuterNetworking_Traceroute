# comptuterNetworking_Traceroute


In this lab you will learn how to implement a traceroute application using ICMP request and reply messages. The checksum and header making are not covered in this lab, refer to the ICMP ping lab for that purpose, the naming of most of the variables and socket is also the same. 

Traceroute is a computer networking diagnostic tool which allows a user to trace the route from a host running the traceroute program to any other host in the world. Traceroute is implemented with ICMP messages. It works by sending ICMP echo (ICMP type ‘8’) messages to the same destination with increasing value of the time-to-live (TTL) field. The routers along the traceroute path return ICMP Time Exceeded (ICMP type ‘11’) when the TTL field becomes zero. The final destination sends an ICMP reply 
(ICMP type ’0’) messages on receiving the ICMP echo request. The IP addresses of the routers which send replies can be extracted from the received packets. The round-trip time between the sending host and a router is determined by setting a timer at the sending host. 

Your task is to develop your own Traceroute application in python using ICMP. Your application will use ICMP but, in order to keep it simple, will not exactly follow the official specification in RFC 1739.

Code
Below you will find the skeleton code for the client. You are to complete the skeleton code. The places where you need to fill in code are marked with #Fill in start and #Fill in end. Each place may require one or more lines of code.

Additional Notes
1. You do not need to be concerned about the checksum, as it is already given in the assignment skeleton code. 
2. This lab requires the use of raw sockets. In some operating systems (e.g. MacOS, Windows), you may need administrator/root privileges to be able to run your Traceroute program. 
3. Local testing may require you to turn your firewall or antivirus software off to allow the messages to be sent and received. However, Gradescope is not impacted by this.
4. See the end of Lab 4 ‘ICMP Pinger’ programming exercise for more information on ICMP. 



What to Hand in
Use your GitHub repository to upload the complete code for the assignment. The name of the file you submit should be “solution.py”.

Testing the Pinger
Test your client by running your code to trace google.com or bing.com. Your output should return a list and meet the acceptance criteria format provided below.

Output Requirements (Acceptance Criteria)
Your code must produce the traceroute output in the format provided below for Gradescope to verify your code is working correctly.

Your trace must collect hop number, roundtrip time (rtt), host ip, and the hostname. If a hostname is not available for a host, you should provide an explicit hostname as “hostname not returnable”. Also, if a host is timing out (not responding), you must record this in your trace list item with the text “Request timed out”. Example provided below:

Example:    1    12ms    10.10.111.10    hop1.com
            2    30ms     10.10.112.10    hostname not returnable
            3    *    Request timed out        
            4    5ms    10.10.110.1    target-host.com

Your get_route() function must return a nested list with trace output. That is, each trace row must be a list that includes the trace results as individual items in the list, which is also inside an overall traceroute list. Example provided below:

Example: [ [‘1’, ‘12ms’, ‘10.10.111.10’, ‘hop1.com’], [‘2’, ‘30ms’, ‘10.10.112.10’, 
‘hostname not returnable’], [‘3’, ‘*’, ‘Request timed out’], [‘4’, ‘5ms’, 
‘10.10.110.1’, ‘target-host.com’] ]

Note: Your output will be parsed to verify that it includes the relevant information, so if you do not provide the output of your function in a nested list, your solution will not work correctly and you will not receive points. Also, note that the example lists include all data as strings.
