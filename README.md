# PythonMunkiScripts

A script I wrote to work with Munki.

The idea is that this script will run on every munki run (hourly) on a given Apple Caching Server

The script is designed to locate and raise an alert if the caching server detects a 'rogue' peer caching server

This rogue peer is usually the result of someone misconfiguring or turning on an apple caching server
and not building it as per our automated method. This results in unexpected bandwidth utilisation 
as the clients might be connecting from another site over a slow internet link.

The script performs a couple of functions:

```
1. 	It will attempt to ensure the caching service is running
	if it is found to be _not_ running, it will attempt to 
	restart the service up to a maximum of 5 times. 
	If this still fails, it will send an email alert

2. 	It will attempt to locate any servers that have registered themselves
	as peer servers. It will then check to see what network those peer
	servers are on, if they are outside of the caching servers range
	of local lan subnets ie from another school or site, it will
	send an alert email to ops to for them to investigate. 
	Ops should then contact the school or office that owns the IP address 
	of the reported Peer server and ask them to shut it down or reconfigure 
	the caching server so that it does not peer outside of the school/office 
	subnet ranges. 
	
	Our Automated build caching servers will only peer with other caching servers
	that are on the same local subnet ie in the same school or office.
	It is HIGHLY recommended that schools use only our build of ACS

Notes:				

In the event that a rogue peer is discovered, we write to a file to 
indicate that an email has been sent, we leave a date time stamp of when 
that email was sent. We check this the next time we attempt to send an email. 
If we send an email successfully in the last 12 hours, we will not send
another one. This is to prevent ops etc from getting spammed by servers that 
have peers or caching service is offline.
```

An example of the email that would be sent in the event of the caching server not being able to be started


```
Subject: [WARNING] Apple Caching _SERVICE_ could not be started at: 1234

The Apple Caching Server at: 1234 is unable to start its caching service. The automated process has attempted to start the process 5 times with a time of 10 seconds between tries. This is more than ample in almost all circumstances. There is likely something wrong with this caching server that needs to be investigated.

Until this is fixed, this caching server will be unable to serve client devices and the WAN link utilisation will be heavily impacted.

Regards,

IT OPS
```

An example of the email that would be sent in the event of the a rogue peer being detected

```
Subject: [WARNING] Rogue Peer detected on Apple Caching Server at: 1234


WARNING!

Rogue Apple Caching Server detected! Rogue Caching Server currently advertising as a peer across sites.

The Caching Server at: 1234 has located the following rogue peer with IP address: 10.10.10.1

You should contact the school or office that owns the IP address: 10.10.10.1 and request they turn off their Caching
server until they configure their Caching server correctly. (Recommend our build!)

Until this is resolved, the rogue Caching server will negatively impact the WAN utilisation at: 1234 as well as potentially many other sites as well as the site at which the rogue Caching server is operating from.

Regards,

IT OPS
```














































