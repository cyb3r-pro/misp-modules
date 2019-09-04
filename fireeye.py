#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, base64, json, re
import requests as req
# Suppressing SSL Warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning, InsecurePlatformWarning, SNIMissingWarning
req.packages.urllib3.disable_warnings(InsecureRequestWarning)
req.packages.urllib3.disable_warnings(InsecurePlatformWarning)
req.packages.urllib3.disable_warnings(SNIMissingWarning)


misperrors = {'error': 'Error'}
mispattributes = {'input': ['domain', 'ip-dst', 'md5', 'email-src'], 
					'output': ['filename', 'md5', 'email-src', 'email-subject', 'hostname', 'ip-dst', 'url', 'filename|md5', 'filename|sha1', 'freetext'] }
moduleinfo = {'version': '0.1',
			  'author': '@j_dubp',
			  'description': 'Query FireEye for alert count (hover) or additional indicators (expansion)',
			  'module-type': ['hover', 'expansion']}
			  
moduleconfig = ['user', 'password', 'hostname']

def handler(q=False):
	# Declare global variables for later use
	global base_uri
	global user_auth

	if q is False:
		return False
	request = json.loads(q)

	if request.get('domain'):
		toquery = 'callback_domain='+request['domain']
	elif request.get('ip-dst'):
		toquery = 'dst_ip='+request['ip-dst']
	elif request.get('md5'):
		toquery = 'md5='+request['md5']	
	elif request.get('email-src'):
		toquery = 'sender_email='+request['email-src']
	else:
		misperrors['error'] = 'Unsupported attributes type'
		return misperrors

	if request.get('config'):
		if (request['config'].get('user') is None) or (request['config'].get('password') is None):
			misperrors['error'] = 'FireEye authentication is incomplete'
			return misperrors
		elif request['config'].get('hostname') is None:
			misperrors['error'] = 'FireEye appliance hostname is missing'
			return misperrors
		else:
			# Set URL
			base_uri = 'https://'+request['config'].get('hostname')+'/wsapis/v1.2.0/'
			# Set authorization -- Python 3 requires strings to be encoded to bytes for base64
			auth = str.encode(request['config'].get('user')+':'+request['config'].get('password'))
			user_auth = base64.b64encode(auth).decode('utf-8')
	else:
		misperrors['error'] = 'FireEye configuration is missing'
		return misperrors

	if 'event_id' in request:
		return handle_expansion(toquery)
	else:
		return handle_hover(toquery)
	
	
def handle_hover(searchVar):
	print('Hover module')
	# Instantiate object from class, authenticating to FireEye
	client = FireeyeClient(user_auth, base_uri)

	# Query alerts for provided indicator
	results = client.alerts(searchVar)	
	
	# Logout to free up sessions
	client.auth_logout()

	# Gather alert count for hover module
	alerts_count = results['alertsCount']
	return {'results': [{'types': mispattributes['output'],
						'values': str(alerts_count)+' FireEye alerts for '+searchVar}]}

def handle_expansion(searchVar):
	print('Expansion module')
	# Whitelist of known good or unwanted IOCs
	url_whitelist = [re.compile('file:\/\/\/'), re.compile('smtpprotoheader')]
	ip_whitelist = [re.compile('(10\.57\.|130\.247\.|137\.136\.|199\.16\.199)')]
	file_whitelist = [re.compile('(svchost|explorer|acrord32|winword|iexplore|reg|mmc|eventvwr|ctfmon|wmiprvse|packager)\.exe', re.I), 
					re.compile('\.(dll|tmp|cust|temp|pip|word|mso|dotm|defa|hdb|lck|ie5|ehdr)', re.I)]
	correlation_whitelist= [re.compile('(powershell|cmd)\.exe', re.I)]
	
	# Regex patterns for URL matching
	url_scheme_pattern = r'(http|ftp|mailto|telnet|ssh)(s){0,1}\:\/\/.*'
	url_scheme_regex = re.compile(url_scheme_pattern, re.I)
	
	to_return = []
	to_return_unique = []
	
	# Instantiate object from class, authenticating to FireEye
	client = FireeyeClient(user_auth, base_uri)

	# Query alerts for provided indicator
	results = client.alerts(searchVar+'&info_level=normal')
	
	# Logout to free up sessions
	client.auth_logout()	

	# Check to see if alert_count is at least 1 before proceeding, otherwise Python will throw an IndexError: list index out of range
	# Loop through all alert data using alert_count - 1
	alerts_count = results['alertsCount']
	alerts_count = int(alerts_count)
	if alerts_count > 0:
		print('Found at least one FireEye alert for '+searchVar)
		# Parse alert data
		count = 0

		while count != alerts_count:
			alert = results['alert'][count]
			malware_sample = alert['explanation']['malwareDetected']['malware']
			os_changes = alert['explanation']['osChanges']
			# Account for times when cncServices does not exist in the JSON
			cnc_services = []
			try:
				cnc_services = alert['explanation']['cncServices']['cncService']
			except:
				pass
			
			# Gather email sample details
			for entry in alert:
				if 'smtpMessage' in entry:
					email_subject = alert['smtpMessage']['subject']
					to_return.append({"values": email_subject, "type": 'email-subject'})
					email_src = alert['src']['smtpMailFrom']
					to_return.append({"values": email_src, "type": 'email-src'})
					
			# Gather malware sample details	
			malware_count = 0
			for entry in malware_sample:
				try:
					if 'md5Sum' in malware_sample[malware_count]:
						sample_hash = malware_sample[malware_count]['md5Sum']	
						to_return.append({"values": sample_hash, "type": 'md5'})					
				except:
					if 'md5Sum' in entry:
						sample_hash = malware_sample['md5Sum']
						to_return.append({"values": sample_hash, "type": 'md5'})	
				try:
					if 'sha256' in malware_sample[malware_count]:
						sample_hash = malware_sample[malware_count]['sha256']	
						to_return.append({"values": sample_hash, "type": 'sha256'})					
				except:
					if 'sha256' in entry:
						sample_hash = malware_sample['sha256']
						to_return.append({"values": sample_hash, "type": 'sha256'})								
				try:
					if 'original' in malware_sample[malware_count]:
						sample_name = malware_sample[malware_count]['original']
						to_return.append({"values": sample_name, "type": 'filename'})					
				except:
					if 'original' in entry:
						sample_name = malware_sample['original']
						to_return.append({"values": sample_name, "type": 'filename'})					
				try:
					if 'url' in malware_sample[malware_count]:
						url = malware_sample[malware_count]['url']
						to_return.append({"values": url, "type": 'url'})	
				except:
					if 'url' in entry:
						url = malware_sample['url']	
						to_return.append({"values": url, "type": 'url'})
				malware_count += 1

			# Gather C2 information
			for item in cnc_services:
				if 'channel' in item:
					user_agent = re.search('~~User-Agent:\s(.*?)::~~', item['channel'])
					if user_agent:
						to_return.append({"values": user_agent.group(1), "type": 'user-agent' })		
				
			# Gather os changes
			for item in os_changes:
				# Network indicators
				if 'network' in item:
					for entry in item['network']:
						if "hostname" in entry:
							to_return.append({"values": entry['hostname'], "type": 'hostname'})					
						if "ipaddress" in entry:
							to_return.append({"values": entry['ipaddress'], "type": 'ip-dst'})
						if "http_request" in entry:
							domain = re.search('~~Host:\s(.*?)~~', entry['http_request'])
							url = re.search('^.*\s(.*?)\sHTTP', entry['http_request'])
							domain_name = ''
							url_string = ''						
							if domain:
								domain_name = domain.group(1)
							if url:
								url_string = url.group(1)
							if domain_name and url_string:
								url = domain_name + url_string
								to_return.append({"values": url, "type": 'url'})
							if url_string:
								to_return.append({"values": url_string, "type": 'pattern-in-traffic'})						
						# Process indicators
						if "md5sum" in entry['processinfo']:
							filename = re.search('([-\.\w\s]+\.[\w]{2,4})', entry['processinfo']['imagepath'])
							if filename:
								file = filename.group(1)
								to_return.append({"values": (file+'|'+entry['processinfo']['md5sum']), "type": 'filename|md5'})
							
				# File indicators
				if 'process' in item:	
					# Look for md5sum in the process data, indicating the data is related to a file
					file_found = False
					for entry in item['process']:
						if 'md5sum' in entry:
							file_found = True
							try:
								md5 = item['process']['md5sum']
							except:
								md5 = entry['md5sum']
							break
					
					if file_found:
						command = ''
						filename = ''
						for entry in item['process']:					
							# Get process command line argument
							if 'cmdline' in entry:
								try:
									command = item['process']['cmdline']
								except: 
									command = entry['cmdline']
								# Replace chars that cause issues in JSON
								command = command.replace('\\', '/')
								command = command.replace('"', '')
							# Gather filename, hash, and command line argument
							if 'value' in entry:
								try:
									filename = re.search('([-\.\w\s]+\.[\w]{2,4})', item['process']['value'])
								except:
									filename = re.search('([-\.\w\s]+\.[\w]{2,4})', entry['value'])									
						if filename:
							file = filename.group(1)
							to_return.append({"values": file+'|'+md5, "type": 'filename|md5', "comment":command})
								
				# This part of the JSON has a lot of temporary and non malicious files -- whitelisting is important here
				if 'file' in item:
					for entry in item['file']:
						# Gather data only if both filename and hash exist
						if 'value' in entry and 'md5sum' in entry:	
							filename = re.search('([-\.\w\s]+\.[\w]{2,4})', entry['value'])						
							if filename:
								file = filename.group(1)					
								to_return.append({"values": file+'|'+entry['md5sum'], "type": 'filename|md5'})	
									
			count += 1

		# Modify current indicator list and append to new list to avoid duplicates
		for item in to_return:
			# Check values against whitelists of known false positives or non-indicators
			if not any(regex.findall(item['values']) for regex in url_whitelist) \
			and not any(regex.findall(item['values']) for regex in ip_whitelist) \
			and not any(regex.findall(item['values']) for regex in file_whitelist):		
				# Disable correlation for specific attributes
				if any(regex.findall(item['values']) for regex in correlation_whitelist):
					item['disable_correlation'] = True		
				# Ensure URLs have scheme, necessary for later parsing
				if item['type'] == 'url':
					url_scheme_match = re.search(url_scheme_regex, item['values'])
					if not url_scheme_match:
						# Modify existing url value in dictionary to include scheme
						item['values'] = 'http://'+item['values']
				# Append item to new de-duplicated list
				if item not in to_return_unique:
					to_return_unique.append(item)
	else:
		print('No alerts found for '+searchVar)
		
	# Return indicators for event expansion
	r = {'results': to_return_unique}
	return r		
	

##
# Class for FireEye-API library
##	
class FireeyeClient(object):
	'''
	Parent object for Fireeye-API library. Creation of this object will allow
	use of the Fireeye API for python based projects
	'''

	def __init__(self, auth, uri, port=443):
		self.port = port
		self.user_auth = auth		
		self.base_uri = uri
		self.auth_login()	
			
	def auth_login(self):
		auth_uri = self.base_uri+'auth/login'
		header = {'Authorization':'Basic '+self.user_auth}
		resp = req.post(auth_uri, headers=header, verify=False)
		if resp.status_code == 200:
			self.token = resp.headers['x-feapi-token']
			self.token_header = {'x-feapi-token':resp.headers['x-feapi-token']}

		else:
			misperrors['error'] = 'FireEye authentication failure with status code:'+str(resp.status_code)+' and message: '+resp.content
			return misperrors

	def auth_logout(self):
		logout_uri = self.base_uri+'auth/logout'
		header = self.token_header
		resp = req.post(logout_uri, headers=header, verify=False)		

	# Return JSON from alerts query			
	def alerts(self, Filters):
		alert_uri = self.base_uri+'alerts?'+Filters
		# Update header content to send back JSON instead of XML
		self.token_header.update({'Accept' : 'application/json'})

		try:
			resp = req.get(alert_uri, headers=self.token_header, verify=False)

			if resp.status_code == 200:
				# Python3 returns bytes, must convert to a string
				r = json.loads(resp.content.decode('utf-8'))
				return r								
							
			else:
				misperrors['error'] = 'Error while checking FireEye alert criteria with status code: ' +str(resp.status_code)
				return misperrors
	
		except (KeyError, IndexError):
			misperrors['error'] = 'Error in FireEye alert query'
			return misperrors		
		
		
def introspection():
	return mispattributes

	
def version():
	moduleinfo['config'] = moduleconfig
	return moduleinfo

if __name__ == "__main__":
	# TESTING
	# For hover module, remove 'event_id' from JSON, for expansion module include 'event_id' in JSON   
	raw_data = { 'md5' : '' , 'event_id' : '1', 'config' : {'user' : 'insert-here' , 
														'password' : 'insert-here', 'hostname' : ''}
														 }
	json_data = json.dumps(raw_data)
	print(handler(q=json_data))
