# android-memory-leak
A memory leak exploit I discovered in 2019 while playing around with WiFi 802.11 Signal Beacons and how android improperly parses and displays the packets in the WiFi menu in Settings

# Explanation (from my knowledge)

Usually a normal beacon packet has the SSID, BSSID and length of the SSID in the packet. When setting the SSID Length byte in the beacon packet to a length longer than the SSID, certain versions of android allocate memory of the same size of this improper length for the SSID and copy the same amount of bytes to that space. In a typical Beacon packet, the SSID is located in the last part of the packet. This means that when Android copies memory from the packet over the length and index of the SSID, it copies and displays memory straight from other locations, outside of where the packet is stored in memory. More in-depth beacon signals contain RSN information after the SSID, however when we ignore this part of the packet and take it out completely, it still is recognized as a valid WiFi beacon packet and is parsed and accepted into the phone for displaying.

```
Beacon Packet Signal: [MAIN PACKET][LENGTH OF SSID][SSID]


Example Packet: 

[Information such as RadioTap type, BSSID & broadcast info etc.]
[SSID LENGTH: 20][SSID: A]


Android:

*Receives packet*
Ok, the SSID Length = 20
*Allocates 20 bytes of memory*
*Copies 20 bytes starting from the SSID Offset 0 which = 'A'*
```

After it copies `A` to the buffer, it has no more content of the beacon packet to copy from, so copies straight from memory and displays it in the WiFi settings. The length of the copied junk-memory is `SSID Length Byte - Actual length of SSID`


# Usage
```
gcc aml.c -o aml

airmon-ng start wlan0     

# This creates a monitor-mode interface from wlan0, typically then called wlan0mon after using airmon-ng. You can use any tools/ways to get the interface into monitor mode

./aml [monitor-mode interface]
```
