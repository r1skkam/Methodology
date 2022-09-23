# Wireless Penetration Testing

## Frequency / bands / Channels
- 2.4 GHz : 11 Channels (14 total, e.g: In Japan)
  - 2.4 GHz = 802.11 b / g / n / ax
- 5 GHz : 45 Channels
  - 5 GHz = 802.11 a / h / j / n / ac / ax
 
<img src="./images/wifi_amendments.png" width="700"/>

#### Overlapping channels for 2.4 GHz  
<img src="./images/overlapping.png" width="500"/>
 
#### Non Overlapping channels for 2.4 GHz (to avoid interferences) with channel bonding  
<img src="./images/nonoverlapping.png" width="500"/>

#### Signal and attenuation 2.4GHz VS 5GHz

<img src="./images/signal.png" width="500"/>

--> The *higher* the frequency of a wireless signal the *shorter* the range.  
--> 2.4GHz (802.11g) covers a substantial larger range than that of 5.0GHz (802.11a)  
--> The higher frequency signals of 5.0GHz do not penetrate solid objects nearly as well as do 2.4GHz signals.  
--> The smaller wavelength of 5.0GHz allows a higher absorption rate by solid objects

<img src="./images/attenuation.png" width="500"/>

#### Antennas

<img src="./images/antennas.png" width="900"/>

## WLAN basics
### Frames

#### Management Frames
- https://mrncciew.com/2014/09/29/cwap-802-11-mgmt-frame-types/

WireShark filter: ```(wlan.fc.type == 0)&&(wlan.fc.type_subtype == 0x0c)```

<img src="./images/management_frames.png" width="500"/>

- [**Beacon Frame**](https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/): It contains all the information about the network. Beacon frames are transmitted periodically, they serve to announce the presence of a wireless LAN and to synchronise the members of the service set. Beacon frames are transmitted by the access point (AP) in an infrastructure basic service set (BSS).

<img src="./images/beaconframe.gif" width="350"/>

- [**Probe Request / Response**](https://mrncciew.com/2014/10/27/cwap-802-11-probe-requestresponse/): Client looking for specific SSID or wildcard SSID which means any SSID available. Probe Requests are send by the client on broadcast. 

<img src="./images/proberesponse.png" width="900"/>

#### Control Frames
- https://mrncciew.com/2014/09/27/cwap-mac-header-frame-control/

#### Data Frames
- https://mrncciew.com/2014/10/13/cwap-802-11-data-frame-types/

### Authentication Types
#### Open Authentication
- Open
- OWE

#### Personal Authentication
- WEP
- WPA/WPA2-PSK
- WPA3-SAE

#### Enterprise Authentication
- WPA/WPA2/WPA3-EAP
  - Methods:
    1. EAP-GTC
    2. EAP-MD5
    3. EAP-PAP
    4. EAP-CHAP
    5. EAP-MSCHAP
    6. EAP-MSCHAPv2
    7. EAP-TLS
    8. EAP-AKA/AKA'
    9. EAP-PWD
    10. EAP-SIM
    11. EAP-NOOB

## Installation / Configuration
It is *highly recommanded* to use a [Kali Linux OS](https://www.kali.org/get-kali/#kali-installer-images) with bare metal install regarding dependencies and current research on WPA3 or tool for WPA2-Enterprise.

Install the driver for ALPHA card.
https://github.com/aircrack-ng/rtl8812au

## Debug and Wi-Fi ninja 
#### Check Wi-Fi card frequency and channel available
```
┌──(lutzenfried㉿xec)-[~/]
└─$ iwlist wlan1 channel    
wlan1     32 channels in total; available frequencies :
          Channel 01 : 2.412 GHz
          Channel 02 : 2.417 GHz
          Channel 03 : 2.422 GHz
          Channel 04 : 2.427 GHz
          Channel 05 : 2.432 GHz
          Channel 06 : 2.437 GHz
          Channel 07 : 2.442 GHz
          Channel 08 : 2.447 GHz
          Channel 09 : 2.452 GHz
          Channel 10 : 2.457 GHz
          Channel 11 : 2.462 GHz
          Channel 12 : 2.467 GHz
          Channel 13 : 2.472 GHz
          Channel 36 : 5.18 GHz
          Channel 40 : 5.2 GHz
          Channel 44 : 5.22 GHz
          Channel 48 : 5.24 GHz
          Channel 52 : 5.26 GHz
          Channel 56 : 5.28 GHz
          Channel 60 : 5.3 GHz
          Channel 64 : 5.32 GHz
          Channel 100 : 5.5 GHz
          Channel 104 : 5.52 GHz
          Channel 108 : 5.54 GHz
          Channel 112 : 5.56 GHz
          Channel 116 : 5.58 GHz
          Channel 120 : 5.6 GHz
          Channel 124 : 5.62 GHz
          Channel 128 : 5.64 GHz
          Channel 132 : 5.66 GHz
          Channel 136 : 5.68 GHz
          Channel 140 : 5.7 GHz
          Current Frequency:2.412 GHz (Channel 1)
```

### Restart networking service and WPA supplicant
```
sudo service networking restart
sudo systemctl restart networking.service 
sudo systemctl restart wpa_supplicant.service
```

### Changing Wi-Fi card channel
```
sudo ifconfig wlan1 down
sudo iwconfig wlan1 channel 64
sudo ifconfig wlan1 up
```

### Changing Wi-Fi card Frequency
```
sudo ifconfig wlan1 down
sudo iwconfig wlan1 freq "5.52G"
sudo ifconfig wlan1 up
```

### Monitor mode
```
airmon-ng start wlan0
```

```
ifconfig wlan0 down
iw dev wlan0 set monitor none
ifconfig wlan0 up
```

### Connect using wpa-supplicant

wpa_supplicant -D nl80211 -i wlan1 -c psk.conf

*psk.conf*
```
network={
    ssid="CompanyWiFi"
    psk="SuperPassword"
    proto=RSN
    key_mgmt=WPA-PSK
    pairwise=CCMP TKIP
    group=CCMP TKIP
}
```

<img src="./images/supplicant.png" width="750"/>

## Recon
```
sudo airodump-ng -i wlan0 -w reconfile --output-format csv
```

--> Within airodump-ng you can press "**a**" key to display ap only / sta only / ap + sta

Scan 5Ghz using *a* band
```
sudo airodump-ng --band a -i wlan1
```

## Hidden SSID
#### With Connected Clients
1. Run airodump-ng on the same channel as of SSID 
```
sudo airodump-ng wlan1 -c 11
```
2. Send deauth packets to clients
3. Client will send probe requests and AP will respond with probe response disclosing the SSID name

#### Without Connected Clients
1. Run dictionary attack
2. Popular [SSID](https://github.com/ytisf/mdk3_6.1/blob/master/useful_files/common-ssids.txt) [dictionary](https://gist.github.com/jgamblin/da795e571fb5f91f9e86a27f2c2f626f) from internet or create one
3. Run automated script to try to connect to each SSID
   
## Passive Sniffing
- Wireless interface into *monitor* mode (**airmon-ng**, **iw** utility)
--> Wireless card can only be on *1 channel* at a time.  

**Tools**: Wireshark, tshark, termshark, tcpdump, airodump-ng, horst
- [Wireshark WLAN filters cheat-sheet](https://semfionetworks.com/wp-content/uploads/2021/04/wireshark_802.11_filters_-_reference_sheet.pdf)

## Preferred Network List (PNL)
The PNL or Preferred Network List is a list of Wi-Fi network names (SSIDs) your device automatically trusts. (PNL is generated from the networks you have connected to over time)

1. Sniff the PNL through probe request emitted by STA (Station/client)
2. Create fake access point with same SSID (Wi-Fi routeur, HostAPD, WiFiPhisher, BetterCap, EAPHammer, airbase-ng, [nodogsplash](https://www.sevenlayers.com/index.php/304-evil-captive-portal))
3. Redirect the connected STA to phishing page / Attack the client (windows client)

<img src="./images/pnl.png" width="500"/>

Hostapd config file for open authentication Wi-Fi network
```
interface=wlan1
driver=nl80211
ssid=GuestCorpWifi
bssid=A5:C4:0D:6A:75:3A
channel=6
```

Hostapd config file for WPA2-PSK authentication
```
interface=wlan1
driver=nl80211
ssid=dex-net
wpa=2
wpa_passphrase=password
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
channel=1

bss=wlan1_0
ssid=dex-network
wpa=2
wpa_passphrase=Password1
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
channel=1
```

Launch fake open authentication Wi-Fi network
```
hostapd open.conf
```

--> You can also use WiFi PineApple to setup a captive portal using the "Evil Portal" infusion.  
- https://wiki.wifipineapple.com/legacy/#!captive_portal.md
- https://github.com/kleo/evilportals

## Open Network

## Beacon flood attack
Beacon flood attack is more a nuisance attack linked to 802.11 protocol weaknesses.
- https://github.com/aircrack-ng/mdk4

You can randomly create SSID or give specific wordlist for SSID names.
```
mdk4 wlan1 b -a -g -f ssid_names.txt
```

<img src="./images/beaconflood.png" width="300"/>

## Deauthentication attack
Deauthentication attack is possible because within WPA2 (PSK and Enterprise (MGT)) the management frames are not protected. Its also more of a nuisance attack but can be usefull (comparing to beacon flood) to deauthenticate an STA (station/client) to intercept WPA2-handshake or redirect STA (station/client) to authenticate against your fake **Radius** server (WPA2-Enterprise).  

--> Deauthentication can also be usefull when bypassing Captive Portal, to force client to reconnect and get their MAC address.  

Deauth using aireplay-ng (-c : client is optional)
```
aireplay-ng -0 100 -a BSSID -c STA/CLIENT wlan1
```

## WPS Pin

Checking within a capture the WLAN with WPS enable
```
wps.wifi_protected_setup_state==2
```


## Guest Network

#### Guest network without password
MAC based restriction or captive portal are bypassable security solution but providing Guest network without password can be worst.

1. Verify the client connected within the guest network can see each other ()
2. Verify Guest network isolation with corporate Wi-Fi, or protected Wi-Fi (WPA/WPA2-PSK/WPA3/WPA2-Enterprise)
3. Verify Guest network isolation with internal corporate network IP range
4. Check if the public source IP from Guest network is the same as from internal corporate or corporate Wi-Fi with authentication
5. Check default creds on network components
6. Check for vulnerabilities (RCE,...) on network components

--> If client isolation is not in place, check to password spray on Windows hosts or attack them (MS17-010, EternalBlue...)

#### MAC based authentication (Captive Portal Bypass)
1. You **first** need to authenticate on the Open Wifi. You will then be redirected to the captive portal.
2. At this time you will need to find a connected STA/Client (you can send **deauth** to a BSSID hosting the open network to increase the chance of getting a valid MAC address from connected STA/Client)
3. MAC change you wlan interface MAC address
  
```
ifconfig wlan1 down
macchanger -m D2:E9:6A:D3:B3:51 wlan1
ifconfig wlan1 up
```

#### Network Isolation

- Validate the network isolation/segmentation between guest wi-fi, captive portal based authentication wi-fi and internal corporate network or Wi-Fi corporate network.

#### Client isolation/separation

#### Azure AD and conditional Access Policy
Sometimes it is possible to bypass conditonal access policy for example regarding *MFA* which can be based on *Source IP Adress* or *Geolocation* from the *Guest Network*.  

This represents a vulnerability and could give to an attacker the ability to get a first foothold.

#### Guest Public IP VS Corporate Public IP
It is important to have a different exit public IP address for any guest regarding the internal network IP.

#### Fake access point with internet access


## WEP
- Wired Equivalent Privacy
- Uses Rivest Cipher 4 (RC4) Stream cipher
- **40** Bit or **104** Bit shared key + **24** Bit IV concatenated to the Shared Key
  --> **64** or **128** Bit encryption key

<img src="./images/wep.jpg" width="700"/>

<img src="./images/mpdu.png" width="700"/>

##### Connecting using wpa_supplicant

```
wpa_supplicant -i wlan0 -c wep.conf
wpa_supplicant -B -i wlan0 -c wep.conf
```

wep.conf
```
network={
    scan_ssid=1
    ssid="WepCorpo"
    key_mgmt=NONE
    wep_key0="Password123"
    wp_tx_keyidx=0
}
```

##### Crack WEP
- 250,000 IVs for cracking 64 bit WEP Key
- 1,500,000 IVs for cracking 128-bit WEP Key

--> You can do passive IV capture (but it will take time)  
OR
--> Inject traffic to force more packets and more IVs (Replay Attack) 
- Capture ARP packet and send to AP, it will send reply.

```
sudo airodump-ng -i wlan1 --bssid 14:D6:4D:26:73:96 -w wep
sudo aireplay-ng -3 -b 14:D6:4D:26:73:96 -h 66:B9:B8:1D:EC:66 wlan1
sudo aircrack-ng wep-01.ivs
```

<img src="./images/wep_attack_arp_replay.png" width="800"/>


## WPA

## WPA2
### WPA2-PSK
#### WPA2-PSK (Deauth + Capture handshake + Crack It)
One of the most known technic to attack WPA2-PSK (Pre Shared Key) is to deauthenticate clients and capture authentication handshake to further brute force it and try to recover clear text password.

##### WPA2-Deauthentication attack (against client)

##### WPA2-Deauthentication attack (against AP)

##### Capture WPA2 Handshake

#### KARMA Attack

#### PMKID

Cracking PMKID hashes using hashcat (newer version of hashcat -m 22000)
```
hashcat -a 0 -m 16800 pmkid.txt ../../wordlists/wordlistsOnex/
```

#### KRACK Attack
- https://www.krackattacks.com/
KRAKC attack or Key Reinstallation Attack

#### FRAG Attack

### WPA2-EAP (Enterprise)

#### WPA2-EAP - Password spray attack
- https://mikeallen.org/blog/2016-10-06-breaking-into-wpa-enterprise-networks-with-air-hammer/


## WPA3
The major improvement of WPA3 is a improved handshake (*Dragonfly-Handshake*) that makes it impossible for attackers to record the *4-Way Handshake* and launch a offline dictionary attack.  

The Dragonfly variant used in WPA3 is also known as *Simultaneous Authentication of Equals* (SAE).

WPA3 improvments:
- Provide mutual authentication
- Negotiate Session Key
- Prevent Offline Dictionary Attacks
- Perfect forward secrecy

WPA3 also introduces *perfect forward secrecy* which prevents attackers from decrypting past traffic after a key breach.

Additionally, WPA3 supports *Protected Management Frames* (PMF) which makes it impossible to launch *de-authentication attacks*.  
---> WPA2 already supports this, therefore this is not a novelty of WPA3. However with WPA, PMF are included from the start in the certification program.

#### ZKP - Zero Knowledge Proof  

Within WPA3 the important improvment come from the new handshake which does not transmit any secrets or credentials.  

A zero knowledge proof is a cartographic protocol that enables one party to to prove to another party that *they know a value x* without conveying any information other than the fact that they know the value of x. 

WPA3 makes use of such a zero knowledge proof to ensure that no secrets of the passwords are transmitted in the *SAE handshake*. The *SAE handshake* is the first handshake realized before classical *4 way handshake* such as in WPA2.

SAE handshake goal is to make sure both handshake participants can be sure that the other party knows that they possess the same and correct password.   
--> Mutual authentication (both parties prove that they have knowledge over the same password.)

### Use WPA3-SAE authentication on Linux
https://askubuntu.com/questions/1290589/how-to-use-wpa3-with-ubuntu-20-04

### WPA3-SAE

SAE : Simultaneous Authentication of Equals (SAE)

<img src="./images/sae.png" width="250"/>

Before executing the DragonFly handshake, the password which may be stored in *ascii* or *unicode* needs to be converted in *group Element P*.  
This *group Element P* will be used within the cryptographic calculation of the handshake.

- P = Password element (PWE)
- P = Hash(pw, STA, AP, counter)

<img src="./images/dragonfly1.png" width="250"/>

Then the *Commit phase* can occur, this phase will be in charge of *negotiating the shared key* between Client and Access Point.

<img src="./images/dragonfly2.png" width="250"/>

Then a last step is realized *confirm phase* to validate both peers negotiate the same key which also proof they both posses the password.

<img src="./images/dragonfly3.png" width="250"/>

Dragonslayer: Implements attacks against EAP-pwd.
- https://github.com/vanhoefm/dragonslayer

Dragondrain: This tool can be used to test to which extent an Access Point is vulnerable to Denial-of-Service attacks against WPA3’s SAE handshake.
- https://github.com/vanhoefm/dragondrain-and-time

Dragontime: This is an experimental tool to perform timing attacks against the SAE handshake if MODP group 22, 23, or 24 is used. Note that most WPA3 implementations by default, do not enable these groups.
- https://github.com/vanhoefm/dragondrain-and-time

Dragonforce: This is an experimental tool which makes the information recover from our timing or cache-based attacks, and performs a password partitioning attack. This is similar to a dictionary attack.
- https://github.com/vanhoefm/dragonforce

#### DragonSlayer
Disable Wi-Fi in network manager before using the scripts
```
sudo nmcli radio wifi off
```

Unblock wifi
```
sudo rfkill unblock wifi
```

#### ATTACK : WPA2 Downgrade

#### 

#### ATTACK : WPA3-Transition Downgrade

#### ATTACK : WPA3-SAE timing or cache password paritioning

#### Dragonblood toolset
Tools used for attacks against dragonfly key exchange. Targeting WPA3-SAE and EAP-PWD.
<https://github.com/vanhoefm/dragonforce>
<https://github.com/vanhoefm/dragondrain-and-time>
<https://github.com/vanhoefm/dragonslayer



### WPA3-EAP

## Wi-Fi Hacking Mind Map

- [Link to the map](https://raw.githubusercontent.com/koutto/pi-pwnbox-rogueap/main/mindmap/WiFi-Hacking-MindMap-v1.png)
<img src="./images/wifi_mindmap.png" width="700"/>

## Other Attacks
#### Fake Captive Portal

- Asking connected client for AD or any sensitive credentials 
- You could also redirect the user to download some binary

#### Fake Open Access Point
The main goal is to create an interesting enough SSID in order for a victim to connect (e.g. SSID: Company-FreeSnacks).  

- Monitor connection from clients
- Directly attacked clients
- MITM their traffic

## Resources
- https://sarwiki.informatik.hu-berlin.de/WPA3_Dragonfly_Handshake#:~:text=The%20major%20improvement%20of%20WPA3,traffic%20after%20a%20key%20breach.

- https://sarwiki.informatik.hu-berlin.de/WPA3_Dragonfly_Handshake#:~:text=The%20major%20improvement%20of%20WPA3,traffic%20after%20a%20key%20breach.

#### Pi-PwnBox Rogue AP
- https://github.com/koutto/pi-pwnbox-rogueap

#### OpenWRT supported devices
- https://openwrt.org/toh/views/toh_extended_all

#### OpenWRT Compatibles routers
- https://openwrt.org/toh/start

#### SSID Oracle Attack on Undisclosed Wi-Fi Preferred Network Lists
- https://www.hindawi.com/journals/wcmc/2018/5153265/

#### Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd
- https://papers.mathyvanhoef.com/dragonblood.pdf


## Tools
- https://github.com/derv82/wifite2
- https://github.com/sensepost/berate_ap
- https://github.com/vanhoefm/krackattacks-poc-zerokey
- https://github.com/ZerBea/hcxtools
- https://github.com/sensepost/hostapd-mana
- https://github.com/sensepost/ppp_sycophant
- https://github.com/sensepost/wpa_sycophant
- https://github.com/s0lst1c3/eaphammer
- https://github.com/vanhoefm/dragonslayer
- https://github.com/vanhoefm/dragondrain-and-time
- https://github.com/vanhoefm/dragonforce
- https://github.com/vanhoefm/fragattacks
- https://github.com/vanhoefm/krackattacks-scripts


To do course
https://github.com/topics/wireless-penetration-testing
https://github.com/Offensive-Wireless/Wireless-Penetration-Testing
https://gist.github.com/dogrocker/86881d2403fee138487054da82d5dc2e
https://github.com/ivan-sincek/wifi-penetration-testing-cheat-sheet#wpawpa2-handshake
https://github.com/ricardojoserf/wifi-pentesting-guide


## Vulnerabilities for WLANs Networks

## Defenses
https://github.com/SYWorks/waidps
http://syworks.blogspot.com/2014/04/waidps-wireless-auditing-intrusion.html


KARMA Attack detection
https://github.com/AlexLynd/WiFi-Pineapple-Detector