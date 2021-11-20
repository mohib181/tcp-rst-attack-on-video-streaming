# tcp-rst-attack-on-video-streaming
tcp reset attack on video streaming service for coursework of CSE-406

The attack tool is written in cpp and built using libtins library. To install libtins library follow the steps mentioned [here](http://libtins.github.io/download/)

The attack is performed on two steps  
  - ARP Spoofing
  - RST Packet Spoofing
  
## ARP Spoofing
  Before ARP Spoofine we need to turn on ip forwarding. To turn on ip forwarding we use the following command  
  ```
  sudo sysctl -w net.ipv4.ip_forward=1
  ```
  If the server and the victim is in same LAN, we need to perform ARP Spoofing on both the server and the victim  
  ```
  g++ arp_spoofing.cpp -o arp.out -ltins  
  sudo ./arp.out <server ip> <victim ip>  
  ``` 
## RST Spoofing
  After arp spoofing, we can start the RST spoofing  
  ```
  g++ sniff_spoofing.cpp -o sniff.out -ltins    
  sudo ./sniff.out <victim ip>  
  ```
