# Network-Scanner
A custom python script to detect devices on a network and return their IP addresses mac addresses and host name. It also pings the returned ip addresses to check if they are reachable. It returns a list of reachable IP's along with their mac addresses and host names. Also does same to the unreachable IP addresses. This script is good for networkl administrators to help them identify the variopus devices connected to a single network.





To run this make sure you have 
## python installed on your pc and added to system variables
## Download npcap from their official website https://npcap.com/#download
What does npcap do?
This script uses the scapy library which relies on layer 2 ARP packets to discover devices on the network. Windows blocks raw packet transmission by default unless NPcap is installed and running in compatibility mode
## Run command prompt as administrator

## Install the scapy library
pip install scapy

##Install requests
pip install requests

## Install netaddr libary
pip install netaddr

## run the script after installing
python scan.py


## Would update this script with more features soon

