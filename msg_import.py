#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import base64
import json
import email.utils
import olefile as OleFile
from email.parser import Parser as EmailParser
from urllib.parse import urlparse


misperrors = {'error': 'Error'}
userConfig = {}

inputSource = ['file']

moduleinfo = {'version': '0.1',
			  'author': '@j_dubp',
			  'description': 'Email import (.msg files) module for MISP',
			  'module-type': ['import']}

# extract_urls : This attempts to extract all URL's from text/html parts of the email
moduleconfig = ["extract_urls"]			  
			  
			  
def handler(q=False):
	if q is False:
		return False
	results = []		

	# Decode and parse email
	request = json.loads(q)

	# request data is always base 64 byte encoded
	data = base64.b64decode(request["data"])

	# Check if we were given a configuration
	config = request.get("config", {})
	# Don't be picky about how the user chooses to say yes to these
	acceptable_config_yes = ['y', 'yes', 'true', 't']	

	# Do we extract URL's from the email.
	extract_urls = config.get("extract_urls", None)
	if (extract_urls is not None and extract_urls.lower() in acceptable_config_yes):
		extract_urls = True
	
	# Parse message
	msg = OleReader(data)
	return parse_msg(msg, extract_urls)

	
# String conversion to support various Python environments
def windowsUnicode(string):
	if string is None:
		return None
	if sys.version_info[0] >= 3:  # Python 3
		return str(string, 'utf_16_le')
	else:  # Python 2
		return unicode(string, 'utf_16_le')

# Parse URLs from plain text
def get_urls_from_plain(email_data):
	list_urls = []	
	url_regex = re.compile(r"((http|ftp|mailto|telnet|ssh)(s){0,1}\:\/\/[\w|\/|\.|\#|\?|\&|\=|\-|\%]+)+", re.VERBOSE | re.MULTILINE)

	for match in url_regex.findall(email_data):
		found_url = match[0].replace('hxxp', 'http')
		found_url = urlparse(found_url).geturl()
		# Strip extra chars
		found_url = re.split(r'''[\', ", \,, \), \}, \\]''', found_url)[0]

		if found_url not in list_urls:
			list_urls.append(found_url)

	return list_urls	

	
# Parse MSG file read in by OleReader class
def parse_msg(msg, extract_urls):
	# Reference: https://msdn.microsoft.com/en-us/library/office/ff861332.aspx
	# Reference: http://cerbero-blog.com/?p=1625

	extract_urls = extract_urls
	results = []
		
	# Extract all header information
	headers = msg._getStringStream('__substg1.0_007D')
	# Parse headers for easier data gathering, replace "\n", "\r", "\t"
	trimmed_headers = re.sub('\r|\n|\t', '', headers.strip())
	parsed_headers = EmailParser().parsestr(headers)	
	results.append({'values' : trimmed_headers, 'type' : 'email-header'})				

	# Get email targets (the addresses that received the email from the header)
	email_targets = set()
	email_targets_regex = re.compile(r'for\s(.*@.*);', re.I)
	email_targets_match = re.finditer(email_targets_regex, headers)
	for match in email_targets_match:
		email_targets.add(match.group(1).strip(' <>'))
	for target in email_targets:
		results.append({'values': target, 'type': 'target-email', 'comment': 'Extracted from email Received header'})			

	# E-Mail MIME Boundry
	mime_boundary_regex = re.compile(r'boundary\=\".*?(?=\")', re.S|re.I)
	mime_boundary_match = re.search(mime_boundary_regex, headers)
	if mime_boundary_match:
		mime_boundary = mime_boundary_match.group().replace('boundary="', '')
		results.append({'values' : mime_boundary, 'type' : 'email-mime-boundary'})			

	# Reply To
	if parsed_headers['reply-to']:
		reply_to = parsed_headers['reply-to']
		results.append({'values' : reply_to.strip(), 'type' : 'email-reply-to'})

	# Return Path
	if parsed_headers['return-path']:
		return_path = parsed_headers['return-path']	
		# May need to split so can return email-src and email-src-display-name
		results.append({'values' : return_path.strip(), 'type' : 'email-src'})			

	# X-Sender
	if parsed_headers['x-sender']:
		x_mailer = parsed_headers['x-sender']
		results.append({'values' : x_mailer, 'type' : 'email-src'})			
			
	# X-Mailer
	if parsed_headers['x-mailer']:
		x_mailer = parsed_headers['x-mailer']
		results.append({'values' : x_mailer, 'type' : 'email-x-mailer'})

	# User-Agent
	if parsed_headers['user-agent']:
		x_mailer = parsed_headers['user-agent']
		results.append({'values' : x_mailer, 'type' : 'user-agent'})					
			
	# Thread Index
	if parsed_headers['thread-index']:
		thread_index = parsed_headers['thread-index']
		results.append({'values' : thread_index, 'type' : 'email-thread-index'})			

	# Message ID
	if parsed_headers['message-id']:
		message_id = parsed_headers['message-id']
		results.append({'values' : message_id, 'type' : 'email-message-id'})

	# Subject
	if msg._getStringStream('__substg1.0_0037'):
		subject = msg._getStringStream('__substg1.0_0037')
		results.append({'values' : subject, 'type' : 'email-subject'})

	# Source
	# Try headers first, otherwise parse from streams
	if parsed_headers['from']:
		sender = parsed_headers['from'] #Amazon Prime <aviator@questionmanyone.stream>	
		try:
			sender_email = sender.split('<')[1].strip('>')
			sender_name = sender.split('<')[0].strip('" ')
			results.append({'values' : sender_email, 'type' : 'email-src'})
			results.append({'values' : sender_name, 'type' : 'email-src-display-name'})
		except:
			results.append({'values' : sender, 'type': 'email-src'})
	else:
		'''
		"From:" is typically 0C1F, however if this is an Microsoft Exchange email (validate using type 0C1E, either "EX" or "SMTP"),
		it is not readable directly without resolving using Exchange.
		'''
		sender_email = msg._getStringStream('__substg1.0_5D01') # 0_5D01001F, 0_5D02001F
		sender_name = msg._getStringStream('__substg1.0_0C1A')
		results.append({'values' : sender_email, 'type' : 'email-src'})
		results.append({'values' : sender_name, 'type' : 'email-src-display-name'})
			
	# Destinations
	recipDirs = []
	for dir_ in msg.listdir():
		if dir_[0].startswith('__recip') and dir_[0] not in recipDirs:
			recipDirs.append(dir_[0])

	for recipDir in recipDirs:
		recip_email = msg._getStringStream([recipDir, '__substg1.0_39FE']) # 0_39FE001F
		#recip_name = msg._getStringStream([recipDir, '__substg1.0_3A20']) # 0_3A20001F 0_3001001F
		results.append({'values' : recip_email, 'type' : 'email-dst'})
		#results.append({'values' : recip_name, 'type' : 'email-dst-display-name'})

	# Get Attachments
	attachDirs = []
	for dir_ in msg.listdir():
		if dir_[0].startswith('__attach') and dir_[0] not in attachDirs:
			attachDirs.append(dir_[0])
				
	attachments = []
	for attachDir in attachDirs:
		long_filename = msg._getStringStream([attachDir, '__substg1.0_3707'])
		short_filename = msg._getStringStream([attachDir, '__substg1.0_3704'])
		# Get attachment data, path is hardcoded due to issues with _getStringStream returning None
		attachment_data = msg._getStream(attachDir+'/__substg1.0_37010102')
			
		# Gather filename for appending
		if long_filename:
			filename = long_filename
		elif short_filename:
			filename = short_filename
			
		if filename:	
			results.append({'values' : filename, 'type' : 'email-attachment'})
			results.append({'values' : filename, 'data' : base64.b64encode(attachment_data).decode(), 'type' : 'malware-sample'})

	# Extract URLs from the message body
	if extract_urls:
		body = msg._getStringStream('__substg1.0_1000')
		urls = get_urls_from_plain(body)
		for url in urls:
			results.append({'values': url, 'type': 'url'})	
			# Parse pattern in traffic from URL
			parsed = urlparse(url)
			if parsed.path:
				results.append({"values": parsed.path, "type": 'pattern-in-traffic'})		

	r = {'results': results}
	return r		
	
	
# Class for reading OLE files to parse	
class OleReader(OleFile.OleFileIO):
	''' 
	Parse using the OLE streams based on reference available at http://www.fileformat.info/format/outlookmsg/index.htm
	'''
	def __init__(self, filename):
		OleFile.OleFileIO.__init__(self, filename)

	def _getStream(self, filename):
		if self.exists(filename):
			stream = self.openstream(filename)
			return stream.read()
		else:
			return None

	def _getStringStream(self, filename, prefer='unicode'):
		'''
		Gets a string representation of the requested filename.
		Checks for both ASCII and Unicode representations and returns
		a value if possible.  If there are both ASCII and Unicode
		versions, then the parameter /prefer/ specifies which will be
		returned.
		'''

		if isinstance(filename, list):
			# Join with slashes to make it easier to append the type
			filename = "/".join(filename)

		asciiVersion = self._getStream(filename + '001E')
		unicodeVersion = windowsUnicode(self._getStream(filename + '001F'))
		if asciiVersion is None:
			return unicodeVersion
		elif unicodeVersion is None:
			return asciiVersion
		else:
			if prefer == 'unicode':
				return unicodeVersion
			else:
				return asciiVersion



def introspection():
	modulesetup = {}
	try:
		modulesetup['userConfig'] = userConfig
	except NameError:
		pass
	try:
		modulesetup['inputSource'] = inputSource
	except NameError:
		pass
	return modulesetup


def version():
	moduleinfo['config'] = moduleconfig
	return moduleinfo

# if __name__ == '__main__':
	# test_msg = ''
	# with open(test_msg, 'rb') as email_file:
		# byte_content = email_file.read()
		# base64_bytes = base64.b64encode(byte_content)
		# base64_string = base64_bytes.decode('cp437')
		# json_data = json.dumps({ 'data' : base64_string , 'config' : {'extract_urls' : 'yes' }})
		# print(handler(q=json_data))