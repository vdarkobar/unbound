
Prepare hosts file
```
sudo nano /etc/hosts
```
```
#Change
127.0.0.1	localhost
127.0.0.1	dns01 dns01
#To
127.0.0.1	localhost
<IP-ADDRESS>	dns01 dns01.<local.domain.name>
```
<br><br>
Install unbound
```
sudo apt install -y unbound net-tools tcpdump systemd-resolved ca-certificates
```
<br><br>
Update root hints
```
wget https://www.internic.net/domain/named.root -qO- | sudo tee /usr/share/dns/root.hints
```
<br><br>
Improve avg response times
```
echo "net.core.rmem_max=8388608" | sudo tee -a /etc/sysctl.conf > /dev/null && sudo sysctl -p
```
<br><br>
Prepare ufw
```
sudo ufw allow 53/udp comment "DNS" && \
sudo ufw allow 53/tcp comment "DNS" && \
sudo ufw allow 853/tcp comment "DNS over TLS" && \
sudo systemctl restart ufw
```
<br><br>
Overriding DHCP settings
```
sudo nano /etc/dhcp/dhclient.conf
```
```
#remove from: request...
domain-name-servers
dhcp6.name-servers

#uncomment and edit/add
prepend domain-name-servers <IP_ADDRESS>;
prepend domain-name-servers 127.0.0.1;
```
```
sudo systemctl restart networking
```
<br><br>
Test installation and DNSSEC Validation  
```
echo && \
dig pve02.lan.home-network.me +short && \
dig -x 192.168.1.11 +short
```  
should return an A record. Note the **ad** flag from the resolver (authenticated data = DNSSEC validation was successful)
```
dig sigok.ippacket.stream
```
should return a SERVFAIL error
```
dig sigfail.ippacket.stream
```
open in browser
```
https://wander.science/projects/dns/dnssec-resolver-test/
```
The first command should give a status report of SERVFAIL and no IP address.  
The second should give NOERROR plus an IP address.
```
dig fail01.dnssec.works
```
```
dig dnssec.works
```
If DNSSEC is functioning correctly, you should NOT get an IP address in response  
to a query for www.dnssec-failed.org, and in the status section of the output, 
you might see SERVFAIL.
```
dig @localhost www.dnssec-failed.org A +dnssec
```
Ensure you get an A record in response and there is an ad (authenticated data) flag in the flags section,  
indicating the data was DNSSEC validated.
```
dig @localhost ietf.org A +dnssec
```
Run tcpdump command to monitor traffics on the interface 'eth0' with DoT port 853  
Move to the client machine and run the below command to access external/internet domain
```
sudo tcpdump -vv -x -X -s 1500 -i ens18 'port 853'
```
Ports
```
ss -tulpn
```
```
netstat -an | grep :53 && \
netstat -an | grep :853
```
<br><br>
*unbound-control* commands

Verify configuration
```
unbound-checkconf
```
Unbound Status
```
unbound-control status
```
List Forwards
```
unbound-control list_forwards
```
Lookup on Cache
```
unbound-control lookup youtube.com
```
Dump Cache
```
unbound-control dump_cache > dns-cache.txt
```
Restore Cache
```
unbound-control load_cache < dns-cache.txt
```
Flush Cache  
Flush Specific Host
```
unbound-control flush www.youtube.com
```
Flush everything
```
unbound-control flush_zone .
```
