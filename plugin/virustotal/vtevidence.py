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
from pathlib import PurePath, PureWindowsPath
from virustotal import vtreport
from virustotal import defaults

from virustotal.vt_ida.disassembler import SearchEvidence


# Data structure for storing search results:
# evidence = [ { content: string|bytes, format: bytes | string, source: string, addr: [ {addr_hex, function, segment} ], ... ]
#            source can be: embedded_ip/domain/url, contated_ip/domain/url, dropped_file, sandbox (sandbox name: action)


class VTEvidence(object):
  MAX_RESULTS_PER_CONTENT = 10
  evidence_idb = []
  vt_report=None

  def __init__(self, report):
    if not report:
      logging.debug('[VT Evidence] No report available.')
    else:
      self.vt_report=report

  def clear(self):
    self.evidence_idb = []
   
  def __filter_address_result(self, content, list_addresses):
    ''' Filter results with the same address (even under different sources) '''
    for element in self.evidence_idb:
      if element['content'] == content:
        for addr_current in element['addresses']: # Current addresses detected
          for addr_new in list_addresses:
            if addr_current['addr'] == addr_new['addr']:
              list_addresses.remove(addr_new)

    return list_addresses
  
  def search(self, content, source, flags):
    evidence_found = False
    se = SearchEvidence()

    if (flags & defaults.FLAG_SEARCH_ASCII) == defaults.FLAG_SEARCH_ASCII:
      logging.debug('[VT Evidence] Searching for %s (ASCII): %s', source, content)      
      evidence_addr = se.search_text(content, self.MAX_RESULTS_PER_CONTENT)
      evidence_addr = self.__filter_address_result(content, evidence_addr) 

      if evidence_addr:
        evidence = {}
        evidence['content'] = content        
        evidence['format'] = 'ascii'
        evidence['source'] = source
        evidence['addresses'] = evidence_addr
        self.evidence_idb.append(evidence)
        evidence_found=True

    if (flags & defaults.FLAG_SEARCH_UTF8) == defaults.FLAG_SEARCH_UTF8:
      content_utf8 = content.encode(encoding='utf-8')
      content_hex = content_utf8.hex(' ')
      logging.debug('[VT Evidence] Searching for %s (UTF-8): %s', source, content)      
      evidence_addr = se.search_bytes(content_hex, self.MAX_RESULTS_PER_CONTENT)
      evidence_addr = self.__filter_address_result(content, evidence_addr) 

      if evidence_addr:
        evidence = {}
        evidence['content'] = content
        evidence['format'] = 'utf-8'
        evidence['source'] = source
        evidence['addresses'] = evidence_addr
        self.evidence_idb.append(evidence)
        evidence_found=True

    if (flags & defaults.FLAG_SEARCH_UTF16LE) == defaults.FLAG_SEARCH_UTF16LE:
      content_utf16 = content.encode(encoding='utf-16-le')
      content_hex = content_utf16.hex(' ')
      logging.debug('[VT Evidence] Searching for %s (UTF-16-LE): %s', source, content)      
      evidence_addr = se.search_bytes(content_hex, self.MAX_RESULTS_PER_CONTENT)
      evidence_addr = self.__filter_address_result(content, evidence_addr) 

      if evidence_addr:
        evidence = {}
        evidence['content'] = content
        evidence['format'] = 'utf-16-le'
        evidence['source'] = source
        evidence['addresses'] = evidence_addr
        self.evidence_idb.append(evidence)
        evidence_found=True

    if (flags & defaults.FLAG_SEARCH_BYTES) == defaults.FLAG_SEARCH_BYTES:
      try:
        content_bytes=bytes(content, 'ascii')
      except:
        content_bytes=bytes(content, 'utf-8')
      content_hex = content_bytes.hex(' ')

      logging.debug('[VT Evidence] Searching for %s (Bytes): %s', source, content)
      evidence_addr = se.search_bytes(content_hex, self.MAX_RESULTS_PER_CONTENT)
      evidence_addr = self.__filter_address_result(content, evidence_addr) 

      if evidence_addr:
        evidence = {}
        evidence['content'] = content        
        evidence['format'] = 'bytes'
        evidence['source'] = source
        evidence['addresses'] = evidence_addr
        self.evidence_idb.append(evidence)
        evidence_found=True
    
    return evidence_found

  def search_filenames(self, flags):
    global vt_report
    file_found = False
    num_names = len(self.vt_report.filenames)
    unique_names = set()

    # Create a set of unique names to avoid duplicated searches
    for i in range(num_names):
      fname = self.vt_report.filenames[i]
      fname_raw = r'{}'.format(fname)

      if '\\' in fname:
        unique_names.add(PureWindowsPath(fname_raw).name)
      else:
        unique_names.add(PurePath(fname_raw).name)

    for fname in unique_names:
      if self.search(fname, 'file names submitted', flags):
        file_found=True      

    return file_found
  
  def search_dropped_files(self, flags):  
    i = 0 
    list_rows = self.vt_report.dropped_files
    num_names=len(list_rows)
    unique_names = set()
    file_found = False

    for i in range(num_names):
        current_row = list_rows[i]
        fname = current_row['name']
        fname_raw = r'{}'.format(fname)
        
        if '\\' in fname:
          unique_names.add(PureWindowsPath(fname_raw).name)
        else:
          unique_names.add(PurePath(fname_raw).name)

    for fname in unique_names:
      if self.search(fname, 'dropped files', flags):
        file_found=True
      
    return file_found

  def search_embedded_domains(self, flags):
    global vt_report
    domain_found = False
    list_domains = list(self.vt_report.get_embedded_domains())
    num_domains = len(list_domains)
    i = 0

    if num_domains:
      while num_domains and (i < num_domains):
        current_domain = list_domains[i]    
        domain_info = self.vt_report.get_embedded_domain(current_domain)
        domain_name = domain_info[0]
        i = i+1
        if self.search(domain_name, 'embedded domains', flags):
          domain_found=True
    return domain_found

  def search_embedded_ips(self, flags):
    global vt_report
    ip_found = False
    list_ips = list(self.vt_report.get_embedded_ips())
    num_ips = len(list_ips)
    i = 0
    if num_ips:
      while num_ips and (i < num_ips):
        current_ip = list_ips[i]    
        ip_info = self.vt_report.get_embedded_ip(current_ip)
        ip_addr = ip_info[0]
        i = i+1
        if self.search(ip_addr, 'embedded IPs', flags):
          ip_found=True
    return ip_found

  def search_embedded_urls(self, flags):
    global vt_report
    url_found = False
    list_urls = list(self.vt_report.get_embedded_urls())
    num_urls = len(list_urls)
    i = 0
    if num_urls:
      while num_urls and (i < num_urls):
        current_url = list_urls[i]    
        url_info = self.vt_report.get_embedded_url(current_url)
        url_name = url_info[0]
        i = i+1
        url_name=url_name.strip('http://')
        url_name=url_name.strip('HTTP://')
        url_name=url_name.rstrip('/')
        if self.search(url_name, 'embedded URLs', flags):
          url_found=True
    return url_found

  def search_contacted_domains(self, flags):
    global vt_report
    domain_found = False
    list_domains = list(self.vt_report.get_contacted_domains())
    num_domains = len(list_domains)
    i = 0

    if num_domains:
      while num_domains and (i < num_domains):
        current_domain = list_domains[i]    
        domain_info = self.vt_report.get_contacted_domain(current_domain)
        domain_name = domain_info[0]
        i = i+1
        if self.search(domain_name, 'contacted domains', flags):
          domain_found=True
    return domain_found


  def search_contacted_ips(self, flags):
    global vt_report
    ip_found = False
    list_ips = list(self.vt_report.get_contacted_ips())
    num_ips = len(list_ips)
    i = 0

    if num_ips:
      while num_ips and (i < num_ips):
        current_ip = list_ips[i]    
        ip_info = self.vt_report.get_contacted_ip(current_ip)
        ip_addr = ip_info[0]
        i = i+1
        if self.search(ip_addr, 'contacted IPs', flags):
          ip_found=True
    return ip_found

  def search_contacted_urls(self, flags):
    global vt_report
    url_found = False
    list_urls = list(self.vt_report.get_contacted_urls())
    num_urls = len(list_urls)
    i = 0

    if num_urls:
      while num_urls and (i < num_urls):
        current_url = list_urls[i]    
        url_info = self.vt_report.get_contacted_url(current_url)
        url_name = url_info[0]
        url_name=url_name.strip('http://')
        url_name=url_name.strip('HTTP://')
        url_name=url_name.rstrip('/')
        i = i+1
        if self.search(url_name, 'contacted URLs', flags):
          url_found=True
    return url_found

  def search_behaviour(self, sandbox_name, flags):
    evidence=None    

    if evidence:
      self.evidence_idb.append(evidence)