# Let Security Exposure scan, keep bad bots out

Blog Post: https://www.blubyte.eu/blog/keep-bad-bots-out-with-netscaler-bot-management

List the IP addresses used by Tenable to scan your surface in a patset, the list is provided by the Tenable.

```
add policy patset PATSET_IP_TENABLE
bind policy patset PATSET_IP_TENABLE "54.93.254.128/26" -index 1
bind policy patset PATSET_IP_TENABLE "3.67.7.128/25" -index 2
bind policy patset PATSET_IP_TENABLE "3.124.123.128/25" -index 3
bind policy patset PATSET_IP_TENABLE "18.194.95.64/26" -index 4
bind policy patset PATSET_IP_TENABLE "13.115.104.128/25" -index 5
bind policy patset PATSET_IP_TENABLE "35.73.219.128/25" -index 6
bind policy patset PATSET_IP_TENABLE "13.213.79.0/24" -index 7
bind policy patset PATSET_IP_TENABLE "18.139.204.0/25" -index 8
bind policy patset PATSET_IP_TENABLE "54.255.254.0/26" -index 9
bind policy patset PATSET_IP_TENABLE "13.210.1.64/26" -index 10
bind policy patset PATSET_IP_TENABLE "3.106.118.128/25" -index 11
bind policy patset PATSET_IP_TENABLE "3.26.100.0/24" -index 12
bind policy patset PATSET_IP_TENABLE "3.108.37.0/24" -index 13
bind policy patset PATSET_IP_TENABLE "3.98.92.0/25" -index 14
bind policy patset PATSET_IP_TENABLE "35.182.14.64/26" -index 15
bind policy patset PATSET_IP_TENABLE "3.251.224.0/24" -index 16
bind policy patset PATSET_IP_TENABLE "18.168.180.128/25" -index 17
bind policy patset PATSET_IP_TENABLE "18.168.224.128/25" -index 18
bind policy patset PATSET_IP_TENABLE "3.9.159.128/25" -index 19
bind policy patset PATSET_IP_TENABLE "35.177.219.0/26" -index 20
bind policy patset PATSET_IP_TENABLE "34.201.223.128/25" -index 21
bind policy patset PATSET_IP_TENABLE "44.192.244.0/24" -index 22
bind policy patset PATSET_IP_TENABLE "44.206.3.0/24" -index 23
bind policy patset PATSET_IP_TENABLE "54.175.125.192/26" -index 24
bind policy patset PATSET_IP_TENABLE "13.59.252.0/25" -index 25
bind policy patset PATSET_IP_TENABLE "18.116.198.0/24" -index 26
bind policy patset PATSET_IP_TENABLE "3.132.217.0/25" -index 27
bind policy patset PATSET_IP_TENABLE "13.56.21.128/25" -index 28
bind policy patset PATSET_IP_TENABLE "34.223.64.0/25" -index 29
bind policy patset PATSET_IP_TENABLE "35.82.51.128/25" -index 30
bind policy patset PATSET_IP_TENABLE "35.86.126.0/24" -index 31
bind policy patset PATSET_IP_TENABLE "35.93.174.0/24" -index 32
bind policy patset PATSET_IP_TENABLE "44.242.181.128/25" -index 33
bind policy patset PATSET_IP_TENABLE "15.228.125.0/24" -index 34
bind policy patset PATSET_IP_TENABLE "51.112.93.0/24" -index 35
bind policy patset PATSET_IP_TENABLE "162.159.129.83/32" -index 36
bind policy patset PATSET_IP_TENABLE "162.159.130.83/32" -index 37
bind policy patset PATSET_IP_TENABLE "162.159.140.26/32" -index 38
bind policy patset PATSET_IP_TENABLE "172.66.0.26/32" -index 39
```

create expression to match client IP against the patset
```
add policy expression EXP_PL_IP_TENABLE "(CLIENT.IP.SRC + \"/32\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(31) + \"/31\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(30) + \"/30\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(29) + \"/29\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(28) + \"/28\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(27) + \"/27\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(26) + \"/26\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(25) + \"/25\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(24) + \"/24\").EQUALS_ANY(\"PATSET_IP_TENABLE\")"
```

create log action to produce audit log when request is blocked
```
add audit messageaction AUDIT_IP_TENABLE INFORMATIONAL q/"mgdlogtype=[STIB_IP_TENABLE] src.ip=[" + CLIENT.IP.SRC + "] scr.prt=[" + CLIENT.TCP.SRCPORT + "] dst.ip=[" + CLIENT.IP.DST + "] dst.prt=[" + CLIENT.TCP.DSTPORT + "] cs_vserver=[" + HTTP.REQ.CS_VSERVER.NAME + "] hostname=[" + HTTP.REQ.HOSTNAME + "] url=[" + HTTP.REQ.URL.PATH_AND_QUERY.SUBSTR(0,200) + "] method=[" + HTTP.REQ.METHOD + "] userid=none User-Agent=[\"" + HTTP.REQ.HEADER("User-Agent") + "\"" + "] referer=[\"" + HTTP.REQ.HEADER("referer").VALUE(0) + "\"" + "] location=[" + CLIENT.IP.SRC.LOCATION + "] Action=[blocked]"/ -logtoNewnslog YES
```

responder policy to block requests from Tenable IPs unless User-Agent contains "Tenable-Scan-CustomerID"
```
add responder policy RS_PL_IP_TENABLE "EXP_PL_IP_TENABLE && HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Tenable-Scan-CustomerID\").NOT" RS_AC_Blocked -logAction AUDIT_IP_TENABLE
```

bind the responder policy to relevant load balancing or content switch vservers
```
bind lb vserver LB_VS_server -policyName RS_PL_IP_TENABLE -priority 100 -gotoPriorityExpression END -type REQUEST
bind cs vserver CS_VS_server -policyName RS_PL_IP_TENABLE -priority 100 -gotoPriorityExpression END -type REQUEST
```
Note: Replace LB_VS_server and CS_VS_server with actual vserver names where the policy needs to be bound.

Add to whitelist BOT MgMt Profile
```
add policy expression EXP_PL_IP_TENABLE "(CLIENT.IP.SRC + \"/32\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(31) + \"/31\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(30) + \"/30\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(29) + \"/29\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(28) + \"/28\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(27) + \"/27\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(26) + \"/26\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(25) + \"/25\").EQUALS_ANY(\"PATSET_IP_TENABLE\") || (CLIENT.IP.SRC.SUBNET(24) + \"/24\").EQUALS_ANY(\"PATSET_IP_TENABLE\")"
bind bot profile Test -whiteList -type EXPRESSION -value "EXP_PL_IP_TENABLE && HTTP.REQ.HEADER(\"User-Agent\").CONTAINS(\"Tenable-Scan-CustomerID\")" -log ON -enabled ON -logMessage "Tenable Scan"
```
