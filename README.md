# Analyseur de trame

Protocoles décodés:

 - Ethernet
 - Null (interfaces de loopback sur macOS et *BSD)
 - *Linux Cooked SLL* (`-i any`)
 - IPv4
 - IPv6 (pas toutes les options)
 - VLAN
 - ICMP (rudimentaire)
 - ICMPv6 (rudimentaire)
 - ARP
 - UDP
 - TCP (pas de réassemblage des paquets)
 - BOOTP/DHCP (beaucoup d'options décodées)
 - DNS (pas de décodage des queries)
 - VXLAN (ethernet dans UDP)

Trois niveaux de verbosité: (flag `-v` répétable)

 - Une ligne par paquet
 - Une ligne par protocole
 - Affichage hexa du contenu des paquets UDP et TCP non gérés

Testé sur macOS et Linux (Debian 9)
