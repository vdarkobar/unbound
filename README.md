<p align="left">
  <a href="https://github.com/vdarkobar/Home-Cloud/blob/main/README.md#create-unbound-dns-optional-pi-hole">Home</a>
</p>  

  
# Unbound *(Pi-Hole)*
validating, recursive, caching DNS resolver with DNS over TLS (DoT), with optional *Pi-Hole* install

  
Clone <a href="https://github.com/vdarkobar/DebianTemplate/blob/main/README.md#debian-template">Template</a>, SSH in using <a href="https://github.com/vdarkobar/Home-Cloud/blob/main/shared/Bastion.md#bastion">Bastion Server</a>  

  
Don't forget to add free space to cloned VM:  
> *VM > Hardware > Hard Disk > Disk Action > Resize*
> *CT > Resources > Root Disk > Volume Action > Resize*   

  
### *Run on VM*:
```
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/unbound/main/setup.sh)"
```
### *Run on CT*:
```
bash -c "$(wget -qLO - https://raw.githubusercontent.com/vdarkobar/unbound/main/setup-ct.sh)"
```
<br><br>
*(steps used to configure <a href="https://github.com/vdarkobar/unbound/blob/main/steps.md">Unbound</a>)*
