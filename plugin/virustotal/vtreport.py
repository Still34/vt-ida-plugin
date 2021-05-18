# Copyright 2020 Google Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__ = 'gerardofn@virustotal.com'

import vt
import logging
from datetime import datetime

SUPPORTED_FILES = ('PEEXE', 'PEDLL', 'MZ', 'MSI', 'COM', 'COFF', 'ELF', 'LINUX', 'MACHO')

class VTReport(object):
  
  def __init__(self, apikey, file_hash, privileges):
    global SUPPORTED_FILES
    client = vt.Client(apikey)
    general = client.get_object('/files/{}',file_hash)
    file_type= general.get('type_tag')
    self.private_api = privileges
    self.compressed_parents = []  # List of Dict
    self.dropped_files = []  # List of Dict
    self.execution_parents = []  # List of Dict
    self.contacted_ips = {}  # Dicc de objetos
    self.contacted_urls = {}  # Dicc de objetos
    self.contacted_domains = {}  # Dicc de objetos
    self.embedded_domains = {}  # Dicc de objetos
    self.embedded_ips = {}  # Dicc de objetos
    self.embedded_urls = {}  # Dicc de objetos

    if file_type.upper() in SUPPORTED_FILES:
      logging.debug('[VT Report] Processing file type %s.', file_type.upper())

      # Public API --------------------------------
      dets = general.get('last_analysis_stats')
      total = dets['harmless'] + dets['malicious'] + dets['suspicious'] + dets['undetected']   
      self.detections_malicious = str(dets['malicious']) 
      self.detections_total = str(total)

      if file_type in ('PEEXE', 'PEDLL'):
        self.creation = datetime.utcfromtimestamp(general.get('creation_date')).strftime('%Y-%m-%d %H:%M:%S')
      else:
        self.creation = None

      self.fs = datetime.utcfromtimestamp(general.get('first_submission_date')).strftime('%Y-%m-%d %H:%M:%S')
      self.ls = datetime.utcfromtimestamp(general.get('last_submission_date')).strftime('%Y-%m-%d %H:%M:%S')
      self.la = datetime.utcfromtimestamp(general.get('last_analysis_date')).strftime('%Y-%m-%d %H:%M:%S')
      self.md5 = general.get('md5')
      self.sha256 = general.get('sha256')
      self.filenames = general.get('names') # List of strings
      self.pe_info = general.get('pe_info') # Object 
      self.packers = general.get('packers')  
      self.tags = general.get('tags')
      self.yara_results = general.get('crowdsourced_yara_results') # list of diccionaries
      self.sigma_results = general.get('sigma_analysis_summary') # dictionary
      self.comments = {}  # Dicc de objetos
      self.behaviour = {}  # Dicc de objetos

      self.trid = general.get('trid')
      
      for comment in client.iterator('/files/{}/comments', file_hash, limit=10):
        self.comments[comment.get('date')] = comment.get('text') # String

      for behaviour in client.iterator('/files/{}/behaviours', file_hash, limit=10):
        self.behaviour[behaviour.get('sandbox_name')] = behaviour # Object

      for dfile in client.iterator('/files/{}/dropped_files', file_hash, limit=10):
        dfile_dict = {}

        if dfile.get('sha256'):
          dfile_dict['sha256'] = dfile.get('sha256') 
          dfile_dict['scanned'] = datetime.utcfromtimestamp(dfile.get('last_analysis_date')).strftime('%Y-%m-%d')
          dfile_dict['type'] = dfile.get('type_description')
          dfile_dict['name'] = dfile.get('meaningful_name')
          detections = dfile.get('last_analysis_stats')
          total = detections['harmless'] + detections['malicious'] + detections['suspicious'] + detections['undetected'] 
          ratio = str(detections['malicious']) + '/' + str(total)
          dfile_dict['detections'] = ratio
        else:  # File not available in VT
          dfile_objectname = str(dfile).split('file ')
          dfile_dict['name'] = dfile_objectname[1]
          dfile_dict['sha256'] = None
          dfile_dict['detections'] = None
          dfile_dict['scanned'] = None
          dfile_dict['type'] = 'File'
          logging.debug('[VT Report] Dropped file not available in VT: %s.', dfile_objectname[1])
        self.dropped_files.append(dfile_dict)
      
      for parent in client.iterator('/files/{}/execution_parents', file_hash, limit=10):
        parent_dict = {}
        parent_dict['sha256'] = parent.get('sha256') 
        parent_dict['scanned'] = datetime.utcfromtimestamp(parent.get('last_analysis_date')).strftime('%Y-%m-%d')
        parent_dict['type'] = parent.get('type_description')
        parent_name = parent.get('meaningful_name')

        if parent_name:
          parent_dict['name'] = parent_name
        else:
          parent_dict['name'] = parent.get('sha256')

        detections = parent.get('last_analysis_stats')
        total = detections['harmless'] + detections['malicious'] + detections['suspicious'] + detections['undetected'] 
        ratio = str(detections['malicious']) + '/' + str(total)
        parent_dict['detections'] = ratio
        self.execution_parents.append(parent_dict)

      for ip in client.iterator('/files/{}/contacted_ips', file_hash, limit=20):
        self.contacted_ips[ip.id] = ip  # Object

      for url in client.iterator('/files/{}/contacted_urls', file_hash, limit=20):
        self.contacted_urls[url.get('url')] = url  # Object

      for domain in client.iterator('/files/{}/contacted_domains', file_hash, limit=20):
        self.contacted_domains[domain.id] = domain  # Object
      
      if self.private_api:
        for domain in client.iterator('/files/{}/embedded_domains', file_hash, limit=20):
          self.embedded_domains[domain.id] = domain  # Object

        for ip in client.iterator('/files/{}/embedded_ips', file_hash, limit=20):
          self.embedded_ips[ip.id] = ip  # Object

        for url in client.iterator('/files/{}/embedded_urls', file_hash, limit=20):
          self.embedded_urls[url.get('url')] = url  # Object

        for parent in client.iterator('/files/{}/compressed_parents', file_hash, limit=10):
          parent_dict = {}
          parent_dict['sha256'] = parent.get('sha256') 
          parent_dict['scanned'] = datetime.utcfromtimestamp(parent.get('last_analysis_date')).strftime('%Y-%m-%d')
          parent_dict['type'] = parent.get('type_description')
          parent_name = parent.get('meaningful_name')

          if parent_name:
            parent_dict['name'] = parent_name
          else:
            parent_dict['name'] = parent.get('sha256')

          detections = parent.get('last_analysis_stats')
          total = detections['harmless'] + detections['malicious'] + detections['suspicious'] + detections['undetected'] 
          ratio = str(detections['malicious']) + '/' + str(total)
          parent_dict['detections'] = ratio
          self.compressed_parents.append(parent_dict)
     
      client.close()
      self.valid_report = True

    else:
      logging.debug('[VT Report] File type {} not supported.', file_type)
      client.close()
      self.valid_report = False

  def list_sandboxes(self):
    if self.behaviour:
      return self.behaviour.keys()
    else:
      return None
  
  def get_sandbox_report(self, sandbox_name): # returns dict
    sandbox = self.behaviour[sandbox_name]
    actions_dict = {}
    
    if (sandbox.get('files_opened')):
      actions_dict['Files opened'] = sandbox.get('files_opened') # list of strings
    if (sandbox.get('files_written')):
      actions_dict['Files written'] = sandbox.get('files_written') # list of strings
    if (sandbox.get('files_deleted')):
      actions_dict['Files deleted'] = sandbox.get('files_deleted') # list of strings

    if (sandbox.get('tags')):
      actions_dict['Tags'] = sandbox.get('tags')

    if (sandbox.get('command_executions')):
      actions_dict['Command executions'] = sandbox.get('command_executions')

    if (sandbox.get('calls_highlighted')):
      actions_dict['Calls highlighted'] = sandbox.get('calls_highlighted')

    if (sandbox.get('processes_terminated')):
      actions_dict['Processes terminated'] = sandbox.get('processes_terminated') # list of strings
    if (sandbox.get('processes_killed')):
      actions_dict['Processes killed'] = sandbox.get('processes_killed') # list of strings
    if (sandbox.get('processes_injected')):
      actions_dict['Processes injected'] = sandbox.get('processes_injected') # list of strings
    if (sandbox.get('processes_created')):
      actions_dict['Processes created'] = sandbox.get('processes_created') # list of strings
    if (sandbox.get('processes_tree')):
      actions_dict['Processes tree'] = sandbox.get('processes_tree') # list of dictionaries

    if (sandbox.get('services_opened')):
      actions_dict['Services opened'] = sandbox.get('services_opened') # list of strings
    if (sandbox.get('services_created')):
      actions_dict['Services created'] = sandbox.get('services_created') # list of strings
    if (sandbox.get('services_started')):
      actions_dict['Services started'] = sandbox.get('services_started') # list of strings
    if (sandbox.get('services_stopped')):
      actions_dict['Services stopped'] = sandbox.get('services_stopped') # list of strings
    if (sandbox.get('services_deleted')):
      actions_dict['Services deleted'] = sandbox.get('services_deleted') # list of strings

    if (sandbox.get('windows_searched')):
      actions_dict['Windows searched'] = sandbox.get('windows_searched') # list of strings
    if (sandbox.get('windows_hidden')):
      actions_dict['Windows hidden'] = sandbox.get('windows_hidden') # list of strings

    if (sandbox.get('mutexes_opened')):
      actions_dict['Mutexes opened'] = sandbox.get('mutexes_opened') # list of strings
    if (sandbox.get('mutexes_created')):
      actions_dict['Mutexes created'] = sandbox.get('mutexes_created') # list of strings

    if (sandbox.get('crypto_algorithms_observed')):
      actions_dict['Crypto alg. observed'] = sandbox.get('crypto_algorithms_observed') # list of strings
    if (sandbox.get('crypto_keys')):
      actions_dict['Crypto keys'] = sandbox.get('crypto_keys') # list of strings    
    if (sandbox.get('crypto_plain_text')):
      actions_dict['Crypto plain texct'] = sandbox.get('crypto_plain_text') # list of strings    

    if (sandbox.get('text_decoded')):
      actions_dict['Text decoded'] = sandbox.get('text_decoded') # list of strings    
    if (sandbox.get('text_highlighted')):
      actions_dict['Text highlighted'] = sandbox.get('text_highlighted') # list of strings    

    if (sandbox.get('ja3_digests')):
      actions_dict['JA3 digests'] = sandbox.get('ja3_digests') # list of strings

    if (sandbox.get('modules_loaded')):
      actions_dict['Modules loaded'] = sandbox.get('modules_loaded') # list of strings

    if (sandbox.get('registry_keys_opened')):
      actions_dict['Reg. keys opened'] = sandbox.get('registry_keys_opened') # list of strings
    if (sandbox.get('registry_keys_set')):
      actions_dict['Reg. keys set'] = sandbox.get('registry_keys_set') # list of dictionaries
    if (sandbox.get('registry_keys_deleted')):
      actions_dict['Reg. keys deleted'] = sandbox.get('registry_keys_deleted') # list of strings

    if (sandbox.get('ids_alerts')):
      actions_dict['IDS alerts'] = sandbox.get('ids_alerts') # list of dictionaries

    return actions_dict

  def get_comments(self):
    return self.comments

  def get_contacted_ips(self):
    return self.contacted_ips.keys()

  def get_contacted_ip(self, ip):  # returns list containing ip + av detections ratio
    ip_report = self.contacted_ips[ip]

    # Format: observable + detections 
    ip_details = []
    ip_analysis = ip_report.get('last_analysis_stats')
    total = ip_analysis['harmless'] + ip_analysis['malicious'] + ip_analysis['suspicious'] + ip_analysis['undetected'] 
    ip_analysis = str(ip_analysis['malicious']) + '/' + str(total)
    ip_details.append(ip)
    ip_details.append(ip_analysis)
    ip_details.append(ip_report.get('country'))
    return ip_details

  def get_embedded_ips(self):
    return self.embedded_ips.keys()

  def get_embedded_ip(self, ip):  
    ip_report = self.embedded_ips[ip]

    # Format: ip + detections + country
    ip_details = []
    ip_analysis = ip_report.get('last_analysis_stats')
    total = ip_analysis['harmless'] + ip_analysis['malicious'] + ip_analysis['suspicious'] + ip_analysis['undetected'] 
    ip_analysis = str(ip_analysis['malicious']) + '/' + str(total)
    ip_details.append(ip)
    ip_details.append(ip_analysis)
    ip_details.append(ip_report.get('country'))
    return ip_details

  def get_contacted_urls(self):
    return self.contacted_urls.keys()

  def get_contacted_url(self, url):  # returns list
    url_report = self.contacted_urls[url]

    # Format: url + detections 
    url_details = []
    url_analysis = url_report.get('last_analysis_stats')
    total = url_analysis['harmless'] + url_analysis['malicious'] + url_analysis['suspicious'] + url_analysis['undetected'] 
    url_analysis = str(url_analysis['malicious']) + '/' + str(total)
    url_details.append(url)
    url_details.append(url_analysis)
    url_details.append(url_report.get('last_analysis_date'))
    return url_details

  def get_embedded_urls(self):
    return self.embedded_urls.keys()

  def get_embedded_url(self, url):  # returns list 
    url_report = self.embedded_urls[url]

    # Format: url + detections + scanned time
    url_details = []
    url_details.append(url)
    detections = url_report.get('last_analysis_stats')
    if detections:
      total = detections['harmless'] + detections['malicious'] + detections['suspicious'] + detections['undetected'] 
      ratio = str(detections['malicious']) + '/' + str(total)
    else:
      ratio = None
    url_details.append(ratio)      
    url_details.append(url_report.get('last_analysis_date'))
    return url_details

  def get_contacted_domains(self):
    return self.contacted_domains.keys()

  def get_contacted_domain(self, domain):  # returns list containing ip + av detections ratio
    domain_report = self.contacted_domains[domain]

    # Format: observable + detections 
    domain_details = []
    domain_analysis = domain_report.get('last_analysis_stats')
    total = domain_analysis['harmless'] + domain_analysis['malicious'] + domain_analysis['suspicious'] + domain_analysis['undetected'] 
    domain_analysis = str(domain_analysis['malicious']) + '/' + str(total)
    domain_details.append(domain) # Domain name
    domain_details.append(domain_analysis) # Domain stats
    domain_details.append(domain_report.get('creation_date')) # Creation date
    domain_details.append(domain_report.get('registrar')) # Registrar

    return domain_details

  def get_embedded_domains(self):
    return self.embedded_domains.keys()

  def get_embedded_domain(self, domain):  # returns list containing ip + av detections ratio
    domain_report = self.embedded_domains[domain]

    # Format: observable + detections 
    domain_details = []
    domain_analysis = domain_report.get('last_analysis_stats')
    total = domain_analysis['harmless'] + domain_analysis['malicious'] + domain_analysis['suspicious'] + domain_analysis['undetected'] 
    domain_analysis = str(domain_analysis['malicious']) + '/' + str(total)
    domain_details.append(domain)
    domain_details.append(domain_analysis)
    domain_details.append(None)
    domain_details.append(domain_report.get('creation_date'))
    domain_details.append(None)

    return domain_details