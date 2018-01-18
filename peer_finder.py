#!/usr/bin/python

import csv
import sys
import subprocess
import plistlib
import socket,struct
import CoreFoundation
import datetime
import time
import smtplib
import os

''' 
Script Name:	peer_finder_post_install.py
Author: 		Calum Hunter
Version:		0.1
Date Modified:	12-06-2017
Purpose:		Peer Finder Script
				This script will perform a couple of functions:

				1. 	It will attempt to ensure the caching service is running
					if it is found to be _not_ running, it will attempt to 
					restart the service up to a maximum of 5 times. 
					If this still fails, it will send an email alert to ops
				
				2. 	It will attempt to locate any servers that have registered themselves
					as peer servers. It will then check to see what network those peer
					servers are on, if they are outside of the caching servers range
					of local lan subnets ie from another school or site, it will
					send an alert email to ops to for them to investigate. 
					Ops should then contact the school or office that owns the IP address 
					of the reported Peer server and ask them to shut it down or reconfigure 
					the caching server so that it does not peer outside of the school/office 
					subnet ranges. 
					
					Our built caching servers will only peer with other caching servers
					that are on the same local subnet ie in the same school or office.
					It is HIGHLY recommended that schools use only our build of ACS

Notes:				In the event that a rogue peer is discovered, we write to a file to 
					indicate that an email has been sent, we leave a date time stamp of when 
					that email was sent. We check this the next time we attempt to send an email. 
					If we send an email successfully in the last 12 hours, we will not send
					another one. This is to prevent ops etc from getting spammed by servers that 
					have peers or caching service is offline.
'''

# Define some base variables
DEBUG = False # Set to true to print extra output to stdout, False to only output on error
LAST_RUN_FILE = "/Library/Preferences/org.company.peer_finder.plist"
SITE_CODE_NUMBER = CoreFoundation.CFPreferencesCopyAppValue(
	"Text1", "com.apple.RemoteDesktop").split(': ')[4].split(",")[0].strip()
LDAP_SERVER = "ldapserver.com"
AD_UNAME = "username@domain"
AD_PWORD = "password"
SITES_CN = "CN=Sites,CN=Configuration,DC=domain,DC=yours"
# Email settings
SMTP_SERVER_ADDRESS = 'mail.server.com'
SMTP_SERVER_PORT = '25'
FROM_EMAIL_ADDRESS = 'alerts@server.com'

# Define our functions here
# If debug mode enabled, be verbose with the output
def log(OUTPUT):
	if DEBUG:
		print OUTPUT

def WritePlist(KeyName, Value):
	log("KeyName: %s" % KeyName)
	log("Value: %s" % Value)
	log("Writing above Key/Value to file: %s" % LAST_RUN_FILE)
	# We use defaults instead of plistlib, because defaults can _update_ a file rather than overwrite it. 
	# PlistLib seems only able to overwrite an entire file rather than update specific key/values in an
	# existing file. This means we also have to convert from binary to xml with plutil after
	# using defaults. Oh well.
	CMD_WRITE = 'defaults write %(last_run_file_path)s %(key_name)s -string "%(value)s"' % {
		'last_run_file_path' : LAST_RUN_FILE,
		'key_name' : KeyName,
		'value' : Value,
	}
	CMD_CONVERT_XML = "plutil -convert xml1 %s" % LAST_RUN_FILE
	try:	
		subprocess.check_output(CMD_WRITE,shell=True)
	except Exception as Error:
		print Error
	else:
		log('[OK] Key/Value written to file successfully.')
		log('Converting to XML...')
		try:
			subprocess.check_output(CMD_CONVERT_XML,shell=True)
		except Exception as Error:
			print Error
		else:
			log('[OK] Plist converted to XML.')

def CheckTime(LAST_RUN_DATE):
	LAST_RUN = datetime.datetime.strptime(LAST_RUN_DATE, "%Y-%m-%d %H:%M:%S")
	CURRENT_TIME = datetime.datetime.now()

	if CURRENT_TIME - datetime.timedelta(hours=12) <= LAST_RUN:
		log('Last sent alert was LESS THAN 12 hours ago')
		log('Do NOT send an alert!')
		return False
	else:
		log('Last sent alert was GREATER THAN 12 hours ago')
		log('Send alert!')
		return True

def ShouldWeSendAnAlert(AlertType):
	if not os.path.isfile(LAST_RUN_FILE):
		# Our file does not exist! We should run our alert
		log('File: %s does not exist!' % LAST_RUN_FILE)
		log('Send alert!')
		return True
	else:
		# Our file DOES exist, we should read it in with plistlib and see when it was last run
		log('File: %s DOES exist, checking for presence of key: %s' % (LAST_RUN_FILE, AlertType))
		LAST_RUN_XML = plistlib.readPlist(LAST_RUN_FILE)
		if AlertType in LAST_RUN_XML:
			LAST_RUN_DATE = LAST_RUN_XML[AlertType]
			log('Key: %s exists' % AlertType)
			log('Value of key is: %s' % LAST_RUN_DATE)
			if CheckTime(LAST_RUN_DATE):
				return True
			else: 
				return False
		else:
			log('Key: %s does not exist' % AlertType)
			log('Send alert!')
			return True # We don't have a key for the request alert type - so go ahead and send our alert

# Check the supplied IP address is within a supplied network subnet
def addressInNetwork(ip, net):
	ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
	netstr, bits = net.split('/')
	netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
	mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
	return (ipaddr & mask) == (netaddr & mask)

# Check the build time and compare it to current time
def CheckBuildTime():
	# Get some variables about the build time and current time
	# Get our image build time, split to get just the date string, then split it into a list
	IMAGED_DATE = CoreFoundation.CFPreferencesCopyAppValue(
		"Text3", "com.apple.RemoteDesktop").split(': ')[2].split()
	# If the TZ is _NOT_ the same as our current local TZ, then change it to match 
	# This is because we have schools that are in different timezones we have to account for
	LOCAL_TZ = time.strftime("%Z")
	if not LOCAL_TZ in IMAGED_DATE[4]:
		IMAGED_DATE = [TZ.replace(IMAGED_DATE[4],LOCAL_TZ) for TZ in IMAGED_DATE]
	# Join our list back into a string so that datetime can create an object out of it
	IMAGED_DATE = ' '.join(IMAGED_DATE)
	IMAGED_DT_OBJ = datetime.datetime.strptime(IMAGED_DATE, "%a %b %d %H:%M:%S %Z %Y")
	IMAGED_EPOCH = time.mktime(datetime.datetime.strptime(
		str(IMAGED_DT_OBJ), '%Y-%m-%d %H:%M:%S').timetuple())
	# Current date information
	CURR_DATE = time.strftime("%a %b %d %H:%M:%S %Z %Y")
	CURR_EPOCH = time.mktime(datetime.datetime.strptime(
		str(CURR_DATE), '%a %b %d %H:%M:%S %Z %Y').timetuple())
	# Our minimum EPOCH number for us to run is the time of build plus 2 hours (7200 seconds)
	MINIMUM_EPOCH_DATE = IMAGED_EPOCH + 7200
	if CURR_EPOCH < MINIMUM_EPOCH_DATE:
		return False
	else:
		return True

# Send email to ops advising of a peer server having been detected
def send_email_summary(SMTP_SERVER_ADDRESS,SMTP_SERVER_PORT,SITE_CODE_NUMBER, NON_LOCAL_PEERS):
	# If we have more than one rogue peer, lets use correct language in our email
	if len(NON_LOCAL_PEERS)>1:
		IS_T = 'are'
		SERVER_T = 'Servers'
		PEER_T =   'peers'
		ADDRESS_T = 'addresses'
		SUBJECT = '[WARNING] Rogue Peers detected on Apple Caching Server at: %s' % (SITE_CODE_NUMBER)
	else:
		IS_T = 'is'
		SERVER_T = 'Server'
		PEER_T = 'peer'
		ADDRESS_T = 'address'
		SUBJECT = '[WARNING] Rogue Peer detected on Apple Caching Server at: %s' % (SITE_CODE_NUMBER)
	RECIP =  ['ops@server.com']
	BCC_RECIP = RECIP.append('admin@server.com')
	BCC_RECIP = RECIP.append('admin2@server.com')
	MESSAGE_BODY = """From: IT OPS <%(from)s>
Subject: %(subject)s
reply-to: <%(from)s>

WARNING!

Rogue Apple Caching %(server)s detected! Rogue Caching %(server)s currently advertising as %(peer)s across sites.

The Caching Server at: %(sitecode)s has located the following rogue %(peer)s with IP %(address)s: %(non_local_peers)s

You should contact the school or office that owns the IP %(address)s: %(non_local_peers)s and request they turn off their Caching %(server)s
until they configure their Caching %(server)s correctly. (Recommend our build!)

Until this is resolved, the rogue Caching %(server)s will negatively impact the WAN utilisation at: %(sitecode)s as well as potentially many other sites
as well as the site at which the rogue Caching %(server)s %(is_are)s operating from.

Regards,

IT OPS

	""" % {
			'from' : FROM_EMAIL_ADDRESS,
			'subject' : SUBJECT,
			'sitecode' : SITE_CODE_NUMBER,
			'non_local_peers' : NON_LOCAL_PEERS,
			'server' : SERVER_T,
			'peer'	: PEER_T,
			'address' : ADDRESS_T,
			'is_are' : IS_T,
		}

	EMAIL_SUMMARY = smtplib.SMTP(SMTP_SERVER_ADDRESS,SMTP_SERVER_PORT)
	try:
		EMAIL_SUMMARY.sendmail(FROM_EMAIL_ADDRESS, RECIP, MESSAGE_BODY)
		print ' [OK] Sent email alert (Rogue Peer Discovery) to: %s' % RECIP
		# Write success to our output file
		NOW = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		WritePlist('RoguePeerLastSent', NOW)
	except Exception as Error:
		print Error
	EMAIL_SUMMARY.quit()

def send_email_caching_service_offline(SMTP_SERVER_ADDRESS,SMTP_SERVER_PORT, SITE_CODE_NUMBER):
# Send email to ops indicating that the caching service on a particular server is not running
# and that attempts to get it started have failed
	RECIP = ['ops@server.com']
	BCC_RECIP = RECIP.append('admin@server.com')
	BCC_RECIP = RECIP.append('admin2@server.com')
	SUBJECT = '[WARNING] Apple Caching _SERVICE_ could not be started at: %s' % SITE_CODE_NUMBER
	MESSAGE_BODY = """From: IT Ops <%s>
Subject: %s
reply-to: <%s>

The Apple Caching Server at: %s is unable to start its caching service. The automated process has attempted
to start the process 5 times with a time of 10 seconds between tries. This is more than ample in almost all 
circumstances. There is likely something wrong with this caching server that needs to be investigated.

Until this is fixed, this caching server will be unable to serve client devices and the WAN link utilisation
will be heavily impacted.

Regards,

IT OPS

""" % (FROM_EMAIL_ADDRESS,SUBJECT,FROM_EMAIL_ADDRESS,SITE_CODE_NUMBER)
	EMAIL_OFFLINE = smtplib.SMTP(SMTP_SERVER_ADDRESS, SMTP_SERVER_PORT)
	try:
		EMAIL_OFFLINE.sendmail(FROM_EMAIL_ADDRESS, RECIP, MESSAGE_BODY)
		print ' [OK] Sent email alert (caching service unable to start) to: %s' % RECIP
		# Write success to our output file
		NOW = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		WritePlist('CacheServiceLastSent', NOW)
	except Exception as Error:
		print Error
	EMAIL_OFFLINE.quit()


#==================== Start the script here ==================#
# Check to see if we should even run this script based on build date and curent date.
log("- Checking our build time, we need to wait 2 hours after build time before running this script...")
if CheckBuildTime() == True:
	log("  [OK] Clear to proceed, we were built more than 2 hours ago.")
	log('')
else:
	print "  [ERROR] Build time was less than 2 hours ago. Exiting script here."
	sys.exit(1)
# Check to ensure that caching server is actually running, if not try to get it running.
# if failure, send email to ops
log("- Checking caching server status....")
CACHING_STATUS_OUTPUT = plistlib.readPlistFromString(
	subprocess.check_output(
		"/Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin -x status caching", 
		shell=True))['state']
MAX_TRIES = 5
if CACHING_STATUS_OUTPUT != "RUNNING":
	while CACHING_STATUS_OUTPUT != "RUNNING":
		print "  [WARNING] Caching server is not running! Attempting to restart in 10 seconds..."
		# Try to start it, wait a moment and check again
		subprocess.Popen(
			['/Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin', 'start', 'caching'])
		# Wait 10 seconds and check again 
		time.sleep(10)
		# Now check the status again, and loop through if we have to and try again
		CACHING_STATUS_OUTPUT = plistlib.readPlistFromString(
		subprocess.check_output(
			"/Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin -x status caching", 
			shell=True))['state']
		MAX_TRIES = MAX_TRIES - 1
		if MAX_TRIES == 0:
			print '  [ERROR] Tried the maxium of 5 times, status is still: %s' % (CACHING_STATUS_OUTPUT)
			if ShouldWeSendAnAlert('CacheServiceLastSent') == True:
				# If we get a True returned, then we should send an alert
				log('We should send an email .....')
				send_email_caching_service_offline(SMTP_SERVER_ADDRESS, SMTP_SERVER_PORT, SITE_CODE_NUMBER)
			sys.exit(0)
else:
	log("  [OK] Caching Server status: %s" % (CACHING_STATUS_OUTPUT))
	log('')
# Check to see if we have any peer servers
log("- Beginning search for Caching Server Peers...")
PEERS_XML = subprocess.check_output(
			   "/Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin -x fullstatus caching", 
			   shell=True)
PEERS_PLIST = plistlib.readPlistFromString(PEERS_XML)
# Check to see if any peers wer found.
if not PEERS_PLIST['Peers']:
	log("  [OK] No Peer caching servers found! Exiting")
	# No peers found and caching server is running happy days! Lets bail here.
	sys.exit(0)
else:
	print "- [WARNING] Discovered Peer server(s)!"
	log("")
	log("- Getting a list of our LAN subnets from AD (siteObjectBL)...")
	LDAP_QUERY = "ldapsearch -LLL -o ldif-wrap=no -H ldap://%s -x -D %s -w %s -b \"%s\" -s sub -a always \"(description=%s*)\" siteObjectBL" % (
		LDAP_SERVER, AD_UNAME, AD_PWORD, SITES_CN, SITE_CODE_NUMBER)
	SITE_OBJECT_RESULT = subprocess.check_output(
		LDAP_QUERY,shell=True).splitlines()
	SITE_CIDR_LIST = []
	for LINE in SITE_OBJECT_RESULT:
		if "siteObjectBL: " in LINE:
			SITE_CIDR = LINE.split("CN=")[1].strip(",")
			log("- Found subnet: %s adding it to our list..." % SITE_CIDR)
			SITE_CIDR_LIST.append(SITE_CIDR)
	log("- Final list of CIDR's this caching server is responsible for: %s" % (
		SITE_CIDR_LIST))
	# Now lets loop through any and all peer servers and see if they are from IP addresses on subnets
	# That we are not responsible for ie. another school or office.
	DISCOVERED_ROGUES = []
	for PEER in PEERS_PLIST['Peers']:
		DISCOVERED_PEER_IP = PEER['address']
		log('')
		log('- Discovered a peer with address: %s ' % DISCOVERED_PEER_IP)
		log(' - Checking if this peer is on any of the local network ranges:')
		# Loop through our local network ranges and see if our peer servers are on any of them, if yes, then YAY
		# move on to the next peer server and check if it is on a local network also
		for NET in SITE_CIDR_LIST:
			RESULT = addressInNetwork(DISCOVERED_PEER_IP,NET)
			log("   - Testing local subnet: %s 	%s" % (NET, RESULT))
			if RESULT == True:
				print '     [OK] Peer server: %s is on a local subnet, this is a perfectly acceptable configuration.' % (DISCOVERED_PEER_IP)
				FINAL_RESULT = True
				break
			else:
				FINAL_RESULT = False
		if FINAL_RESULT == False:
			DISCOVERED_ROGUES.append(DISCOVERED_PEER_IP)
			print """     [ERROR]	Peer server: %s is not on any local subnets! It is likely the owner of this peer server 
		has misconfigured their server. An email will be sent to ops for them to investigate.""" % (DISCOVERED_PEER_IP)
			log('')
if DISCOVERED_ROGUES:
	if ShouldWeSendAnAlert('RoguePeerLastSent'):
		# If we get a True returned, then we should send an alert
		log('We should send an email .....')
		send_email_summary(SMTP_SERVER_ADDRESS, SMTP_SERVER_PORT, SITE_CODE_NUMBER, DISCOVERED_ROGUES)


		