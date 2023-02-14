# Getting Started:
## Linux usage
To use these two bash script in linux you must make them as executable:
```
chmod +x ip_discover.sh
```
```
chmod +x nmap_ips.sh
```

After this you can use them.
**Remember that nmap_ips.sh needs file from which read the ips to scan**

How to run it:
```
./ip_discover.sh > ip.txt
``` 
```
./nmap_ips.sh ip.txt
```
