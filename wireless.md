# Wireless Penetration Testing

## Frequency / bands / Channels
- 2.4 GHz : 11 Channels (14 total, e.g: In Japan)
- 5 GHz : 45 Channels

- 2.4 GHz = 802.11 b / g / n / ax
- 5 GHz = 802.11 a / h / j / n / ac / ax
 
<img src="./images/wifi_amendments.png" width="700"/>

Overlapping channels for 2.4 GHz
<img src="./images/overlapping.png" width="500"/>

Non Overlapping channels for 2.4 GHz (to avoid interferences) with channel bonding
<img src="./images/nonoverlapping.png" width="500"/>

### Signal and attenuation 2.4GHz VS 5GHz

<img src="./images/signal.png" width="500"/>

--> The *higher* the frequency of a wireless signal the *shorter* the range.  
--> 2.4GHz (802.11g) covers a substantial larger range than that of 5.0GHz (802.11a)  
--> The higher frequency signals of 5.0GHz do not penetrate solid objects nearly as well as do 2.4GHz signals.  
--> The smaller wavelength of 5.0GHz allows a higher absorption rate by solid objects

<img src="./images/attenuation.png" width="500"/>

## Installation / Configuration
It is *highly recommanded* to use a [Kali Linux OS](https://www.kali.org/get-kali/#kali-installer-images) with bare metal install regarding dependencies and current research on WPA3 or tool for WPA2-Enterprise.

Install the driver for ALPHA card.
https://github.com/aircrack-ng/rtl8812au

## Check Wi-Fi card frequency and channel available
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

## Restart networking service and WPA supplicant
```
sudo service networking restart
sudo systemctl restart networking.service 
sudo systemctl restart wpa_supplicant.service
```
## Changing Wi-Fi card channel
```
sudo ifconfig wlan1 down
sudo iwconfig wlan1 channel 64
sudo ifconfig wlan1 up
```

## Changing Wi-Fi card Frequency
```
sudo ifconfig wlan1 down
sudo iwconfig wlan1 freq "5.52G"
sudo ifconfig wlan1 up
```
                                    

## Recon
```
sudo airodump-ng -i wlan0 -w reconfile --output-format csv
```

Scan 5Ghz using *a* band
```
sudo airodump-ng --band a -i wlan1
```

## Captive Portal
From pwnie express or Wi-Fi physical device you can connect on *Open* Wireless network using the followings commands:
```
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode ad-hoc
sudo ifconfig wlan0 up
```
--> The *WLAN0* card is now in *ad-hoc* mode.  


```
sudo iwlist wlan0 scan OR nmcli dev wifi list
sudo iwconfig wlan0 essid OnexVisitor
```

Listing connection using nmcli and deleting connection
```
sudo nmcli connection show
sudo nmcli connection delete ee849992-5b40-4767-8583-cf9150abf7dd
```

## WPS Pin

## Guest Network

#### Guest network without password

#### Mac based authentication

#### Network Isolation

#### Client isolation/separation

#### Azure AD and conditional Access Policy
Sometimes it is possible to bypass conditonal access policy for example regarding *MFA* which can be based on *Source IP Adress* or *Geolocation* from the *Guest Network*.  

This represents a vulnerability and could give to an attacker the ability to get a first foothold.

#### Guest Exposed IP VS Corporate Exposed IP
It is important to have a different exit IP address 

## WEP

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

## Resources
- https://sarwiki.informatik.hu-berlin.de/WPA3_Dragonfly_Handshake#:~:text=The%20major%20improvement%20of%20WPA3,traffic%20after%20a%20key%20breach.
- https://sarwiki.informatik.hu-berlin.de/WPA3_Dragonfly_Handshake#:~:text=The%20major%20improvement%20of%20WPA3,traffic%20after%20a%20key%20breach.

##### Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd
- https://papers.mathyvanhoef.com/dragonblood.pdf



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