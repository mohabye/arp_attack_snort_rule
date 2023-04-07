# arp_attack
In this rule, we're looking for ARP packets where the source IP address (arp_spa) does not match the target IP address (arp_tpa) and the source MAC address (arp_sha) does not match the target MAC address (arp_tha). 

![images](https://user-images.githubusercontent.com/76062472/230625522-ab9f4cc7-1ff9-4be5-b2dc-233c17d93111.jpg)


This is an indication that an attacker is trying to associate their MAC address with another device's IP address.

The "alert" keyword triggers an alert when the rule is matched. The "msg" keyword specifies the message that will be displayed in the alert. The "sid" keyword assigns a unique ID to the rule, and the "rev" keyword specifies the revision number of the rule.

You can customize this rule based on your network environment and security needs. Make sure to test the rule thoroughly before deploying it in a production environment 

EX :
Suppose you have a network with three devices: A, B, and C. Device A has an IP address of 192.168.1.1, device B has an IP address of 192.168.1.2, and device C has an IP address of 192.168.1.3.

An attacker, with a MAC address of 00:11:22:33:44:55, wants to perform an ARP poisoning attack by associating their MAC address with device B's IP address (192.168.1.2) to intercept network traffic.

The attacker sends an ARP packet with a falsified source MAC address (00:11:22:33:44:55) and a falsified source IP address (192.168.1.1) to device B, pretending to be device A. The packet contains the following information:

arp_op: ARP Request
arp_spa: 192.168.1.1 (pretending to be device A)
arp_tpa: 192.168.1.2 (target IP address, device B's IP)
arp_sha: 00:11:22:33:44:55 (pretending to be device A)
arp_tha: 00:00:00:00:00:00 (unknown target MAC address)
When Snort receives this packet, it matches the packet against the ARP poisoning attack detection rule:
alert arp any any -> any any (msg:"ARP Poisoning Attack Detected"; 
                          arp_spa!=arp_tpa && arp_sha!=arp_tha;
                          sid:100001; rev:1;)
The rule triggers an alert because the source IP address (arp_spa) does not match the target IP address (arp_tpa) and the source MAC address (arp_sha) does not match the target MAC address (arp_tha), which is a sign of an ARP poisoning attack.

Snort generates an alert message, such as "ARP Poisoning Attack Detected", and logs information about the packet, including the source and destination IP and MAC addresses, and the timestamp. This alert can be used by network administrators to take action and investigate the source of the attack.

In summary, the Snort rule for ARP poisoning attack detection works by analyzing ARP packets on the network and triggering an alert when it detects abnormal MAC address associations, which can indicate an ARP spoofing attack
