
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

Install unbound
```
sudo apt install -y unbound net-tools tcpdump systemd-resolved ca-certificates
```

Update root hints
```
wget https://www.internic.net/domain/named.root -qO- | sudo tee /usr/share/dns/root.hints
```

Improve avg response times
```
echo "net.core.rmem_max=8388608" | sudo tee -a /etc/sysctl.conf > /dev/null && sudo sysctl -p
```

Prepare ufw
```
sudo ufw allow 53/udp comment "DNS" && \
sudo ufw allow 53/tcp comment "DNS" && \
sudo ufw allow 853/tcp comment "DNS over TLS" && \
sudo systemctl restart ufw
```
