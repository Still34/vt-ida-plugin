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

import idaapi
import ida_kernwin
from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
from virustotal.vtreport import VTReport
from virustotal.vt_ida.ui.panel import Ui_panelUI
from virustotal import vtevidence
from virustotal import defaults
from virustotal.vt_ida.disassembler import NavigateDisassembler
from datetime import datetime
from math import ceil
import logging
import binascii


class VTWidgets(object):

  @staticmethod
  def show_info(msg):
    ida_kernwin.info(msg)

  @staticmethod
  def show_warning(msg):
    ida_kernwin.warning(msg)


class VTPanel(PluginForm):
  vt_report = None
  vt_evidence = None
  community_index=0
  private_api=False

  def set_privileges(self, privs):
    self.private_api=privs

  def OnCreate(self, form):
    """
    Called when the plugin form is created
    """
    self.parent = self.FormToPyQtWidget(form)
    self.__populateForm()
    
  def __populateForm(self):
    self.panel = Ui_panelUI()
    self.panel.setupUi(self.parent)
    self.panel.retranslateUi(self.parent)

  def __show_contacted_domains(self):
    # Preconf
    list_domain = list(self.vt_report.get_contacted_domains())
    num_domains = len(list_domain)
    self.panel.tw_contacted.setColumnCount(4)
    self.panel.tw_contacted.setRowCount(num_domains)
    self.panel.tw_contacted.setHorizontalHeaderLabels(['Domain', 'Detections', 'Created', 'Registrar'])
    i = 0
  
    if num_domains:
      self.panel.tw_contacted.setRowCount(num_domains) 
      while i < num_domains:
        current_domain = list_domain[i]    
        domain_info = self.vt_report.get_contacted_domain(current_domain)
        # Observable              
        self.panel.tw_contacted.setItem(i, 0, QtWidgets.QTableWidgetItem(domain_info[0]))
        # Detections
        self.panel.tw_contacted.setItem(i, 1, QtWidgets.QTableWidgetItem(domain_info[1]))
        # Creation date
        if domain_info[2] is None:
          self.panel.tw_contacted.setItem(i, 2, QtWidgets.QTableWidgetItem(''))
        else:
          created_time = datetime.utcfromtimestamp(domain_info[2]).strftime('%Y-%m-%d %H:%M:%S')
          self.panel.tw_contacted.setItem(i, 3, QtWidgets.QTableWidgetItem(created_time))
        # Registrar
        if domain_info[3] is None:
          self.panel.tw_contacted.setItem(i, 3, QtWidgets.QTableWidgetItem(''));
        else:
          self.panel.tw_contacted.setItem(i, 3, QtWidgets.QTableWidgetItem(domain_info[3]));
        i = i+1
    else:
      self.panel.tw_contacted.setRowCount(0) 

    # final configuration
    #self.panel.tw_contacted.resizeColumnsToContents()
    self.panel.tw_contacted.resizeRowsToContents()

  def __show_embedded_domains(self):

    list_domains = list(self.vt_report.get_embedded_domains())
    num_domains = len(list_domains)
    self.panel.tw_embedded.setRowCount(num_domains)
    self.panel.tw_embedded.setColumnCount(5)
    self.panel.tw_embedded.setHorizontalHeaderLabels(['Domain', 'Detections', 'Scanned', 'Created', 'Country'])
    i = 0

    if num_domains:
      self.panel.tw_embedded.setRowCount(num_domains) 
      while num_domains and (i < num_domains):
        current_domain = list_domains[i]    
        domain_info = self.vt_report.get_embedded_domain(current_domain)
        # Observable            
        self.panel.tw_embedded.setItem(i, 0, QtWidgets.QTableWidgetItem(domain_info[0]))
        # Detections
        self.panel.tw_embedded.setItem(i, 1, QtWidgets.QTableWidgetItem(domain_info[1]))
        # Scanned
        if domain_info[2] is None: 
          self.panel.tw_embedded.setItem(i, 2, QtWidgets.QTableWidgetItem(''))
        else:
          self.panel.tw_embedded.setItem(i, 2, QtWidgets.QTableWidgetItem(domain_info[2]))
        # Created
        if domain_info[3] is None: 
          self.panel.tw_embedded.setItem(i, 3, QtWidgets.QTableWidgetItem(''));
        else:
          created_time = datetime.utcfromtimestamp(domain_info[3]).strftime('%Y-%m-%d %H:%M:%S')
          self.panel.tw_embedded.setItem(i, 3, QtWidgets.QTableWidgetItem(created_time))
        # Country
        if domain_info[4] is None: 
          self.panel.tw_embedded.setItem(i, 4, QtWidgets.QTableWidgetItem(''));
        else:
           self.panel.tw_embedded.setItem(i, 4, QtWidgets.QTableWidgetItem(domain_info[4]))
        i = i+1
    else:
      self.panel.tw_embedded.setRowCount(0) 

    #self.panel.tw_embedded.resizeColumnsToContents()
    self.panel.tw_embedded.resizeRowsToContents()

  def __show_embedded_ips(self):
    list_ips = list(self.vt_report.get_embedded_ips())
    num_ips = len(list_ips)
    self.panel.tw_embedded.setRowCount(num_ips)
    self.panel.tw_embedded.setColumnCount(3)
    self.panel.tw_embedded.setHorizontalHeaderLabels(['IP', 'Detections', 'Country'])
    i = 0

    if num_ips:
      self.panel.tw_embedded.setRowCount(num_ips) 
      while num_ips and (i < num_ips):
        current_ip = list_ips[i]    
        ip_info = self.vt_report.get_embedded_ip(current_ip)
        # IP
        self.panel.tw_embedded.setItem(i, 0, QtWidgets.QTableWidgetItem(ip_info[0]))
        # Detections
        self.panel.tw_embedded.setItem(i, 1, QtWidgets.QTableWidgetItem(ip_info[1]))
        # Country
        if ip_info[2] is None: 
          self.panel.tw_embedded.setItem(i, 4, QtWidgets.QTableWidgetItem(''));
        else:
           self.panel.tw_embedded.setItem(i, 4, QtWidgets.QTableWidgetItem(ip_info[2]))
        i = i+1
    else:
      self.panel.tw_embedded.setRowCount(0) 

    #self.panel.tw_embedded.resizeColumnsToContents()
    self.panel.tw_embedded.resizeRowsToContents()

  def __show_contacted_ips(self):
    list_ips = list(self.vt_report.get_contacted_ips())
    num_ips = len(list_ips)
    self.panel.tw_contacted.setRowCount(num_ips)
    self.panel.tw_contacted.setColumnCount(3)
    self.panel.tw_contacted.setHorizontalHeaderLabels(['IP', 'Detections', 'Country'])
    i = 0

    if num_ips:
      self.panel.tw_contacted.setRowCount(num_ips) 
      while num_ips and (i < num_ips):
        current_ip = list_ips[i]    
        ip_info = self.vt_report.get_contacted_ip(current_ip)
        # IP
        self.panel.tw_contacted.setItem(i, 0, QtWidgets.QTableWidgetItem(ip_info[0]))
        # Detections
        self.panel.tw_contacted.setItem(i, 1, QtWidgets.QTableWidgetItem(ip_info[1]))
        # Country
        if ip_info[2] is None: 
          self.panel.tw_contacted.setItem(i, 4, QtWidgets.QTableWidgetItem(''));
        else:
           self.panel.tw_contacted.setItem(i, 4, QtWidgets.QTableWidgetItem(ip_info[2]))
        i = i+1
    else:
      self.panel.tw_contacted.setRowCount(0) 

    #self.panel.tw_contacted.resizeColumnsToContents()
    self.panel.tw_contacted.resizeRowsToContents()

  def __show_embedded_urls(self):
    list_urls = list(self.vt_report.get_embedded_urls())
    num_urls = len(list_urls)
    self.panel.tw_embedded.setRowCount(num_urls)
    self.panel.tw_embedded.setColumnCount(3)
    self.panel.tw_embedded.setHorizontalHeaderLabels(['IP', 'Detections', 'Scanned'])
    i = 0

    if num_urls:
      self.panel.tw_embedded.setRowCount(num_urls) 
      while num_urls and (i < num_urls):
        current_url = list_urls[i]    
        url_info = self.vt_report.get_embedded_url(current_url)
        # URL
        self.panel.tw_embedded.setItem(i, 0, QtWidgets.QTableWidgetItem(url_info[0]))
        # Detections
        self.panel.tw_embedded.setItem(i, 1, QtWidgets.QTableWidgetItem(url_info[1]))
        # Scanned
        if url_info[2] is None: 
          self.panel.tw_embedded.setItem(i, 4, QtWidgets.QTableWidgetItem(''));
        else:
           self.panel.tw_embedded.setItem(i, 4, QtWidgets.QTableWidgetItem(url_info[2]))
        i = i+1
    else:
      self.panel.tw_embedded.setRowCount(0) 

    #self.panel.tw_embedded.resizeColumnsToContents()
    self.panel.tw_embedded.resizeRowsToContents()

  def __show_contacted_urls(self):
    list_urls = list(self.vt_report.get_contacted_urls())
    num_urls = len(list_urls)
    self.panel.tw_contacted.setRowCount(num_urls)
    self.panel.tw_contacted.setColumnCount(3)
    self.panel.tw_contacted.setHorizontalHeaderLabels(['URL', 'Detections', 'Scanned'])
    i = 0

    if num_urls:
      self.panel.tw_contacted.setRowCount(num_urls) 
      while num_urls and (i < num_urls):
        current_url = list_urls[i]    
        url_info = self.vt_report.get_contacted_url(current_url)
        # URL
        self.panel.tw_contacted.setItem(i, 0, QtWidgets.QTableWidgetItem(url_info[0]))
        # Detections
        self.panel.tw_contacted.setItem(i, 1, QtWidgets.QTableWidgetItem(url_info[1]))
        # Scanned
        if url_info[2] is None: 
          self.panel.tw_contacted.setItem(i, 4, QtWidgets.QTableWidgetItem(''));
        else:
           self.panel.tw_contacted.setItem(i, 4, QtWidgets.QTableWidgetItem(url_info[2]))
        i = i+1
    else:
      self.panel.tw_contacted.setRowCount(0) 

    #self.panel.tw_contacted.resizeColumnsToContents()
    self.panel.tw_contacted.resizeRowsToContents()

  def __show_yaras(self):
    yaras = self.vt_report.yara_results
    if yaras:
      yara_dict=yaras[self.community_index]
      cm_out='<b>' + 'Rule Name: ' + '</b>' + yara_dict['rule_name'] + '<br>'
      cm_out=cm_out + '<b>' + 'Description: ' + '</b>' + yara_dict['description'] + '<br>'
      cm_out=cm_out + '<b>' + 'Author: ' + '</b>' + yara_dict['author'] + '<br>'
      cm_out=cm_out + '<b>' + 'Ruleset Name: ' + '</b>' + yara_dict['ruleset_name'] + '<br>'
      cm_out=cm_out + '<b>' + 'Source: ' + '</b>' + yara_dict['source'] + '<br>'
      self.panel.tb_community.setText(cm_out)
      self.panel.pb_prev_msg.setEnabled(True)
      self.panel.pb_next_msg.setEnabled(True)
    else: 
      self.panel.tb_community.clear()
      self.panel.pb_prev_msg.setEnabled(False)
      self.panel.pb_next_msg.setEnabled(False)

  def __show_sigmas(self):
    sigmas_dict = self.vt_report.sigma_results
    if sigmas_dict:
      sigma_keys=list(sigmas_dict.keys())
      skey = sigma_keys[self.community_index]
      cm_out='<b>' + 'Rule Name: ' + '</b>' + skey + '<br>'
      risk_dict=sigmas_dict[skey]
      risk_str = 'Critical: ' + str(risk_dict['critical']) + ' High: ' + str(risk_dict['high']) + ' Medium: ' + str(risk_dict['medium']) + ' Low: ' + str(risk_dict['low'])
      cm_out=cm_out + '<b>' + 'Risk: ' + '</b>' + risk_str + '<br>'
      self.panel.tb_community.setText(cm_out)
      self.panel.pb_prev_msg.setEnabled(True)
      self.panel.pb_next_msg.setEnabled(True)
    else:
      self.panel.tb_community.clear()
      self.panel.pb_prev_msg.setEnabled(False)
      self.panel.pb_next_msg.setEnabled(False)

  def __show_comments(self):
    comment_dict = self.vt_report.get_comments()
    if comment_dict:
      comment_keys = list(comment_dict.keys())
      cdate = comment_keys[self.community_index]
      comment = "<br />".join(comment_dict[cdate].split("\n"))
      cm_out = '<b>Date: </b>' + datetime.utcfromtimestamp(cdate).strftime('%Y-%m-%d %H:%M:%S') + '<br>' + '<b>Content: </b>' + comment 
      self.panel.tb_community.setText(cm_out)
      self.panel.pb_prev_msg.setEnabled(True)
      self.panel.pb_next_msg.setEnabled(True)
    else: 
      self.panel.tb_community.clear()
      self.panel.pb_prev_msg.setEnabled(False)
      self.panel.pb_next_msg.setEnabled(False)

  def __community_forward(self):
    value = str(self.panel.cb_select_source.currentText())
    if value == "Comments": 
      comment_dict = self.vt_report.get_comments()
      comment_keys = list(comment_dict.keys())
      if (self.community_index + 1) < len(comment_keys):
        self.community_index =self.community_index+1
        self.__show_comments()
    elif value== "Crowdsourced Sigma rules":
      sigmas_dict = self.vt_report.sigma_results
      sigma_keys=list(sigmas_dict.keys())
      if (self.community_index + 1) < len(sigma_keys):
        self.community_index =self.community_index+1
        self.__show_sigmas()
    elif value=="Crowdsourced Yara rules":
      yaras = self.vt_report.yara_results
      if (self.community_index + 1) < len(yaras):
        self.community_index =self.community_index+1
        self.__show_yaras()

  def __community_backward(self):
    value = str(self.panel.cb_select_source.currentText())
    if (self.community_index - 1) >= 0:
      self.community_index =self.community_index-1

    if value == "Comments": 
        self.__show_comments()
    elif value== "Crowdsourced Sigma rules":
        self.__show_sigmas()
    elif value=="Crowdsourced Yara rules":
        self.__show_yaras()
  
  def __show_compressed_parents(self):
    if self.private_api:
      i = 0 
      list_rows = self.vt_report.compressed_parents
      rows=len(list_rows)
      if rows:
        self.panel.tw_related.setRowCount(rows) 
        while rows and (i < rows):
          current_row = list_rows[i]
          # Name
          self.panel.tw_related.setItem(i, 0, QtWidgets.QTableWidgetItem(current_row['name']))
          # Type
          self.panel.tw_related.setItem(i, 1, QtWidgets.QTableWidgetItem(current_row['type']))
          # Detections
          self.panel.tw_related.setItem(i, 2, QtWidgets.QTableWidgetItem(current_row['detections']))
          # Scanned
          self.panel.tw_related.setItem(i, 3, QtWidgets.QTableWidgetItem(current_row['scanned']))
          i = i+1
      else:
        self.panel.tw_related.setRowCount(0) 
        #self.panel.tw_related.clear()
      self.panel.tw_related.horizontalHeader().setVisible(True)

    else:
      self.panel.tw_related.setEnabled(False)
      self.panel.tw_related.horizontalHeader().setVisible(False)
      self.panel.tw_related.setRowCount(0) 
      self.panel.tw_related.clear()

    self.panel.tw_related.setHorizontalHeaderLabels(['Name', 'Type', 'Detections', 'Scanned'])
    self.panel.tw_related.resizeColumnsToContents()
    self.panel.tw_related.resizeRowsToContents()
    self.panel.tw_related.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)

  def __show_execution_parents(self):
    i = 0 
    list_rows = self.vt_report.execution_parents
    rows=len(list_rows)
    self.panel.tw_related.setEnabled(True)

    if rows:
      self.panel.tw_related.setRowCount(rows) 
      while rows and (i < rows):
        current_row = list_rows[i]
        # Name
        self.panel.tw_related.setItem(i, 0, QtWidgets.QTableWidgetItem(current_row['name']))
        # Type
        self.panel.tw_related.setItem(i, 1, QtWidgets.QTableWidgetItem(current_row['type']))
        # Detections
        self.panel.tw_related.setItem(i, 2, QtWidgets.QTableWidgetItem(current_row['detections']))
        # Scanned
        self.panel.tw_related.setItem(i, 3, QtWidgets.QTableWidgetItem(current_row['scanned']))
        i = i+1
    else:
      self.panel.tw_related.setRowCount(0)
      #self.panel.tw_related.clear()

    self.panel.tw_related.setHorizontalHeaderLabels(['Name', 'Type', 'Detections', 'Scanned'])
    self.panel.tw_related.resizeColumnsToContents()
    self.panel.tw_related.resizeRowsToContents()
    self.panel.tw_related.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)

  def __show_dropped_files(self):
    i = 0 
    list_rows = self.vt_report.dropped_files
    rows=len(list_rows)
    self.panel.tw_related.setEnabled(True)

    if rows:
      self.panel.tw_related.setRowCount(rows) 
      while rows and (i < rows):
        current_row = list_rows[i]
        # Name
        self.panel.tw_related.setItem(i, 0, QtWidgets.QTableWidgetItem(current_row['name']))      
        # Type
        self.panel.tw_related.setItem(i, 1, QtWidgets.QTableWidgetItem(current_row['type']))
        # Detections
        self.panel.tw_related.setItem(i, 2, QtWidgets.QTableWidgetItem(current_row['detections']))
        # Scanned
        self.panel.tw_related.setItem(i, 3, QtWidgets.QTableWidgetItem(current_row['scanned']))
        i = i+1
    else:
      self.panel.tw_related.setRowCount(0)
      #self.panel.tw_related.clear()

    self.panel.tw_related.setHorizontalHeaderLabels(['Name', 'Type', 'Detections', 'Scanned'])
    self.panel.tw_related.horizontalHeader().setVisible(True)
    self.panel.tw_related.resizeColumnsToContents()
    self.panel.tw_related.resizeRowsToContents()
    #self.panel.tw_related.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
    
  def __contacted_selected(self, value):
    if value=="ip addresses": 
      self.__show_contacted_ips()
    elif value== "domains":
      self.__show_contacted_domains()
    elif value=="urls":
      self.__show_contacted_urls()

  def __embedded_selected(self, value):
    if value=="ip addresses": 
      self.__show_embedded_ips()
    elif value== "domains":
      self.__show_embedded_domains()
    elif value=="urls":
      self.__show_embedded_urls()

  def __source_selected(self, value):
    self.community_index=0
    if value=="Comments": 
      self.__show_comments()
    elif value== "Crowdsourced Sigma rules":
      self.__show_sigmas()
    elif value=="Crowdsourced Yara rules":
      self.__show_yaras()

  def __related_selected(self, value):
    if value=="compressed parents": 
      self.__show_compressed_parents()
    elif value== "execution parents":
      self.__show_execution_parents()
    elif value== "dropped files":
      self.__show_dropped_files()

  def __sandbox_selected(self, value):
    self.panel.cb_select_sandbox_action.clear()
    sb_actions_dict=self.vt_report.get_sandbox_report(value)
    sb_actions_keys = list(sb_actions_dict.keys())

    for key in sb_actions_keys:
      self.panel.cb_select_sandbox_action.addItem(key)

    first_action = sb_actions_keys[0]
    self.panel.cb_select_sandbox_action.setCurrentText(first_action)
    #self.sandboxActionSelected(first_action)

  def __sandbox_action_selected(self, value):  
    if value != '':
      sb_name=self.panel.cb_select_sandbox.currentText()
      sb_actions_dict=self.vt_report.get_sandbox_report(sb_name)

      if value in ('Files written','Processes terminated','Files opened', 'Files deleted', 'Tags', 'Command executions', 
      'Calls highlighted', 'Processes created', 'Mutexes created', 'Mutexes opened', 'Text highlighted', 'Modules loaded',
      'Reg. keys opened','Reg. keys deleted', 'Processes injected', 'Services opened', 'Processes killed', 'Services created',
      'Services started','Services stopped','Services deleted','Windows searched','Windows hidden', 'Crypto alg. observed',
      'Crypto keys','Crypto plain texct','Text decoded','JA3 digests'):
        self.panel.tw_behaviour.setColumnCount(1)
        self.panel.tw_behaviour.setHorizontalHeaderLabels(['Name'])
        i = 0 
        list_rows = sb_actions_dict[value]
        rows=len(list_rows)

        if rows:
          self.panel.tw_behaviour.setRowCount(rows) 
          while rows and (i < rows):
            current_row = list_rows[i]    
            # Name
            self.panel.tw_behaviour.setItem(i, 0, QtWidgets.QTableWidgetItem(current_row))
            i = i+1
        else:
          self.panel.tw_behaviour.setRowCount(0)

      elif value in ('Reg. keys set'):
        self.panel.tw_behaviour.setColumnCount(2)
        self.panel.tw_behaviour.setHorizontalHeaderLabels(['Name', 'Value'])
        i = 0 
        list_rows = sb_actions_dict[value]
        rows=len(list_rows)

        if rows:
          self.panel.tw_behaviour.setRowCount(rows) 
          while rows and (i < rows):
            current_row = list_rows[i]
            # Name
            self.panel.tw_behaviour.setItem(i, 0, QtWidgets.QTableWidgetItem(current_row['key']))
            if 'value' in current_row.keys():
              # Value
              self.panel.tw_behaviour.setItem(i, 1, QtWidgets.QTableWidgetItem(current_row['value']))
            i = i+1
        else:
          self.panel.tw_behaviour.setRowCount(0)

      elif value in ('Processes tree',):
        self.panel.tw_behaviour.setColumnCount(2)
        self.panel.tw_behaviour.setHorizontalHeaderLabels(['Name', 'Children'])
        i = 0 
        list_rows = sb_actions_dict[value]
        rows=len(list_rows)

        if rows:
          self.panel.tw_behaviour.setRowCount(rows) 
          while rows and (i < rows):
            current_row = list_rows[i]
            # Name
            self.panel.tw_behaviour.setItem(i, 0, QtWidgets.QTableWidgetItem(current_row['name']))
            if 'children' in current_row.keys():
              # Children
              children=''
              for child in current_row['children']:
                if children != '':
                  children = children + ','
                children =  children + child['name'] 
              self.panel.tw_behaviour.setItem(i, 1, QtWidgets.QTableWidgetItem(children))
            i = i+1
        else:
          self.panel.tw_behaviour.setRowCount(0)

      elif value in ('IDS alerts',):
        self.panel.tw_behaviour.setColumnCount(4)
        self.panel.tw_behaviour.setHorizontalHeaderLabels(['SID', 'Severity', 'Description', 'Source'])
        i = 0 
        list_rows = sb_actions_dict[value]
        rows=len(list_rows)

        if rows:
          self.panel.tw_behaviour.setRowCount(rows) 
          while rows and (i < rows):
            current_row = list_rows[i]
            self.panel.tw_behaviour.setItem(i, 0, QtWidgets.QTableWidgetItem(current_row['rule_id']))
            if 'alert_severity' in current_row.keys():
              self.panel.tw_behaviour.setItem(i, 1, QtWidgets.QTableWidgetItem(current_row['alert_severity']))
            if 'rule_msg' in current_row.keys():
              self.panel.tw_behaviour.setItem(i, 2, QtWidgets.QTableWidgetItem(current_row['rule_msg']))
            if 'rule_source' in current_row.keys():
              self.panel.tw_behaviour.setItem(i, 3, QtWidgets.QTableWidgetItem(current_row['rule_source']))
            i = i+1
        else:
          self.panel.tw_behaviour.setRowCount(0)

      self.panel.tw_behaviour.resizeColumnsToContents()
      #self.panel.tw_behaviour.resizeRowsToContents()

  def set_default_data(self, report):
    _translate = QtCore.QCoreApplication.translate
    self.vt_report = report

    ### General info
    self.panel.le_md5.setText(self.vt_report.md5)
    self.panel.le_Sha256.setText(self.vt_report.sha256)
    self.panel.le_creationtime.setText(self.vt_report.creation)
    self.panel.le_fs.setText(self.vt_report.fs)
    self.panel.le_ls.setText(self.vt_report.ls)
    self.panel.le_la.setText(self.vt_report.la)
    self.panel.ratio_malicious.setText(self.vt_report.detections_malicious)
    self.panel.ratio_malicious.setStyleSheet('color: red')
    self.panel.ratio_total.setText(self.vt_report.detections_total)
    self.panel.ratio_total.setStyleSheet('color: blue')
    header_stylesheet = "::section{Background-color:#3A4EFF;color:#FFFFFF;}"

    ### Tags
    tags_len = len(self.vt_report.tags)
    
    if tags_len:
      rows = ceil(tags_len / 4)
      self.panel.tw_tags.setRowCount(rows)
      #self.panel.tw_tags.setShowGrid(False)
      row = 0
      i = 0
      while row < rows:
        self.panel.tw_tags.setItem(row, 0, QtWidgets.QTableWidgetItem(self.vt_report.tags[i]))
        i=i+1
        if i<tags_len:
            self.panel.tw_tags.setItem(row, 1, QtWidgets.QTableWidgetItem(self.vt_report.tags[i]))
            i=i+1
        if i<tags_len:
            self.panel.tw_tags.setItem(row, 2, QtWidgets.QTableWidgetItem(self.vt_report.tags[i]))
            i=i+1
        if i<tags_len:
            self.panel.tw_tags.setItem(row, 3, QtWidgets.QTableWidgetItem(self.vt_report.tags[i]))
            i=i+1            
        row = row +1 
    self.panel.tw_tags.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
    self.panel.tw_tags.resizeColumnsToContents()

    ### Names
    num_names = len(self.vt_report.filenames)
    fnames = ''
    
    for i in range(num_names):
      fname = self.vt_report.filenames[i]
      if i != 0:
          fnames = fnames + '\n' + fname
      else:
          fnames = fname
    self.panel.tb_filenames.insertPlainText(_translate("VirusTotal",fnames))

    ### Packers info
    if self.vt_report.packers:
      packer_ids = list(self.vt_report.packers.keys())
      rows = len(packer_ids)
      i = 0
      self.panel.tw_packersinfo.setRowCount(rows)
      while rows and (i<rows):
        self.panel.tw_packersinfo.setItem(i, 0, QtWidgets.QTableWidgetItem(packer_ids[i]))
        packer_desc=self.vt_report.packers[packer_ids[i]]
        self.panel.tw_packersinfo.setItem(i, 1, QtWidgets.QTableWidgetItem(packer_desc))
        i = i+1

      ### TRID (to include in the previous widget)
      i = rows # starting at the last row position
      rows = rows + len(self.vt_report.trid)
      j = 0
      self.panel.tw_packersinfo.setRowCount(rows)
      while rows and (i<rows):
        current_row = self.vt_report.trid[j]
        self.panel.tw_packersinfo.setItem(i, 0, QtWidgets.QTableWidgetItem('TrID'))
        desc=current_row['file_type'] + '(' + str(current_row['probability']) + '%)'
        self.panel.tw_packersinfo.setItem(i, 1, QtWidgets.QTableWidgetItem(desc))
        i = i+1
        j = j+1

    #self.panel.tw_packersinfo.resizeColumnsToContents()
    self.panel.tw_packersinfo.horizontalHeader().setStyleSheet(header_stylesheet)

    ### Comments
    self.panel.pb_prev_msg.clicked.connect(self.__community_backward)
    self.panel.pb_next_msg.clicked.connect(self.__community_forward)
    self.panel.cb_select_source.currentTextChanged.connect(self.__source_selected)
    self.__show_comments()

    ### Related
    self.panel.cb_related.currentTextChanged.connect(self.__related_selected)
    self.panel.tw_related.setAlternatingRowColors(True)    
    self.panel.tw_related.horizontalHeader().setVisible(True)
    self.panel.tw_related.horizontalHeader().setStyleSheet(header_stylesheet)
    self.panel.tw_related.setColumnCount(4)
    self.__show_compressed_parents()
   
    ### Contacted observables
    self.__show_contacted_domains()
    self.panel.tw_contacted.horizontalHeader().setStyleSheet(header_stylesheet)
    self.panel.cb_select_contacted.currentTextChanged.connect(self.__contacted_selected)

    ### Behaviour
    self.panel.tw_behaviour.horizontalHeader().setStyleSheet(header_stylesheet)

    if self.vt_report.list_sandboxes():
      sb_keys=list(self.vt_report.list_sandboxes())
      for key in sb_keys:
        self.panel.cb_select_sandbox.addItem(key)
      first_sndbox = sb_keys[0]
      self.panel.cb_select_sandbox.setCurrentText(first_sndbox)

      sb_actions_dict=self.vt_report.get_sandbox_report(first_sndbox)
      sb_actions_keys = list(sb_actions_dict.keys())
      for key in sb_actions_keys:
        self.panel.cb_select_sandbox_action.addItem(key)
      first_action = sb_actions_keys[0]
      self.panel.cb_select_sandbox_action.setCurrentText(first_action)
      self.__sandbox_action_selected(first_action)
    
      self.panel.cb_select_sandbox.currentTextChanged.connect(self.__sandbox_selected)
      self.panel.cb_select_sandbox_action.currentTextChanged.connect(self.__sandbox_action_selected)

    else:
      ### Disable everything
      logging.debug('[VT Panel] Report not available.')
      self.panel.tab_info.setEnabled(False)
      self.panel.tab_analysis.setEnabled(False)

    if self.private_api:
      self.panel.api_key_type.setText('ENTERPRISE')

      ### Embedded observables
      self.panel.tw_embedded.setAlternatingRowColors(True)
      self.panel.tw_embedded.setShowGrid(True)
      self.panel.tw_embedded.setGridStyle(QtCore.Qt.DashLine)
      self.panel.tw_embedded.setCornerButtonEnabled(True)
      self.panel.tw_embedded.setObjectName("tw_embedded")
      self.panel.tw_embedded.horizontalHeader().setVisible(True)
      self.panel.tw_embedded.horizontalHeader().setStyleSheet(header_stylesheet)

      self.panel.cb_select_embedded.currentTextChanged.connect(self.__embedded_selected)
      self.__show_embedded_domains()
      
    else:
      self.panel.cb_select_embedded.setEnabled(False)
      self.panel.tw_embedded.setEnabled(False)
      self.panel.api_key_type.setText('COMMUNITY')

    #### Evidence Panel 
    #self.panel.tab_evidence.setEnabled(False)
    self.panel.pb_search_code.clicked.connect(self.__search_evidence)
    self.panel.pb_go_evidence.clicked.connect(self.__go_to_evidence)
    self.panel.treew_evidence.itemSelectionChanged.connect(self.__evidence_selected)

  def __evidence_selected(self):
    evidence = self.panel.treew_evidence.selectedItems()
    self.panel.tw_behaviour_actions.clear()
    self.panel.tw_behaviour_actions.setRowCount(0)
    #self.panel.tw_behaviour_actions.setShowGrid(False)
    
    if evidence:
      baseNode = evidence[0]
      str_evidence = baseNode.text(0)
      str_addr = baseNode.text(1)
      list_uniqueactions = set()

      # Look for str_evidence in every sandbox/action obtained from VT
      if str_addr and self.vt_report.list_sandboxes():
        sb_names=list(self.vt_report.list_sandboxes())
        for sb_name in sb_names:
          sb_actions_dict=self.vt_report.get_sandbox_report(sb_name)
          sb_actions_keys = list(sb_actions_dict.keys())

          for action in sb_actions_keys:
            list_actions = sb_actions_dict[action]
            num_actions=len(list_actions)
            i = 0 
            if num_actions:
              while num_actions and (i < num_actions):
                value = list_actions[i]   
                if str_evidence in value:
                  list_uniqueactions.add(action)
                i = i + 1 
      
      if list_uniqueactions:
        num_actions = len(list_uniqueactions)
        rows = ceil(num_actions / 3)
        self.panel.tw_behaviour_actions.setRowCount(rows)
        row = 0
        column = 0
        for text in list_uniqueactions:
            self.panel.tw_behaviour_actions.setItem(row, column, QtWidgets.QTableWidgetItem(text))        
            column = column + 1
            if column == 3:
              row = row + 1 
              column = 0
      self.panel.tw_behaviour_actions.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
      self.panel.tw_behaviour_actions.resizeColumnsToContents()

  def __go_to_evidence(self):
    evidence = self.panel.treew_evidence.selectedItems()
    if evidence:
        baseNode = evidence[0]
        str_ea = baseNode.text(1)
        NavigateDisassembler.go_to_ea(str_ea)

  def __search_evidence(self):
    flags = defaults.FLAG_SEARCH_ASCII | defaults.FLAG_SEARCH_BYTES  | defaults.FLAG_SEARCH_UTF16LE | defaults.FLAG_SEARCH_UTF8
    ida_kernwin.show_wait_box("Looking for evidence...")
    self.vt_evidence = vtevidence.VTEvidence(self.vt_report)
    self.vt_evidence.clear()
    self.panel.treew_evidence.clear()

    selected_source = self.panel.cb_select_source_2.currentText()

    if not ida_kernwin.user_cancelled():
      if selected_source in ('All', 'File names submitted'):
        ida_kernwin.replace_wait_box("Searching for evidence: file names")
        self.vt_evidence.search_filenames(flags)
    else:
      logging.info('[VT Panel] Action canceled by the user.')

    if not ida_kernwin.user_cancelled():
      if selected_source in ('All', 'Dropped files'):
        ida_kernwin.replace_wait_box("Searching for evidence: dropped file")
        self.vt_evidence.search_dropped_files(flags)
    else:
      logging.info('[VT Panel] Action canceled by the user.')

    if not ida_kernwin.user_cancelled(): 
      if selected_source in ('All', 'Contacted observables'):
        ida_kernwin.replace_wait_box("Searching for evidence: contacted domains")
        self.vt_evidence.search_contacted_domains(flags)
    else:
      logging.info('[VT Panel] Action canceled by the user.')

    if not ida_kernwin.user_cancelled():
      if selected_source in ('All', 'Contacted observables'):
        ida_kernwin.replace_wait_box("Searching for evidence: contacted IPs")
        self.vt_evidence.search_contacted_ips(flags)
    else:
      logging.info('[VT Panel] Action canceled by the user.')

    if not ida_kernwin.user_cancelled():
      if selected_source in ('All', 'Contacted observables'):
        ida_kernwin.replace_wait_box("Searching for evidence: contacted URLs")
        self.vt_evidence.search_contacted_urls(flags)
    else:
      logging.info('[VT Panel] Action canceled by the user.')

    if not ida_kernwin.user_cancelled():
      if selected_source in ('All', 'Behaviour'):
        if self.vt_report.list_sandboxes():
          sandbox_names=list(self.vt_report.list_sandboxes())
          if sandbox_names:
            for name in sandbox_names:
              ida_kernwin.replace_wait_box("Searching for evidence: sandbox %s" % name)
              self.vt_evidence.search_behaviour(name, flags)
    else:
      logging.info('[VT Panel] Action canceled by the user.')

    if not ida_kernwin.user_cancelled():
      if self.private_api:
        if selected_source in ('All', 'Embedded observables'):
          ida_kernwin.replace_wait_box("Searching for evidence: embedded domains")
          self.vt_evidence.search_embedded_domains(flags)
        if not ida_kernwin.user_cancelled():
          if selected_source in ('All', 'Embedded observables'):
            ida_kernwin.replace_wait_box("Searching for evidence: embedded IPs")
            self.vt_evidence.search_embedded_ips(flags)
        if not ida_kernwin.user_cancelled():
          if selected_source in ('All', 'Embedded observables'):
            ida_kernwin.replace_wait_box("Searching for evidence: embedded URLs")
            self.vt_evidence.search_embedded_urls(flags)
    else:
      logging.info('[VT Panel] Action canceled by the user.')

    ida_kernwin.hide_wait_box()
    logging.debug('[VT Panel] Search results: %s', self.vt_evidence.evidence_idb)

    if self.vt_evidence.evidence_idb:
      self.showEvidence()
    else:
      logging.info('[VT Panel] No evidence found.')


  def showEvidenceGroup(self, list_evidence, group):
      root = QtWidgets.QTreeWidgetItem(self.panel.treew_evidence)
      root.setText(0, group)
      for evidence in list_evidence:
        list_addr = evidence['addresses']
        for addr in list_addr:
          item = QtWidgets.QTreeWidgetItem(root)
          item.setText(0, evidence['content'])
          addre = addr['addr']
          item.setText(1, hex(addre))
          item.setText(2, evidence['format'])
          if evidence['action']:
            item.setText(3, evidence['action'])

  def showEvidence(self):
    list_filenames = []
    list_dropped = []
    list_embedded = []
    list_contacted = []
    list_behaviour = []

    for evidence in self.vt_evidence.evidence_idb:
      if evidence['group'] == 'file names':
        list_filenames.append(evidence)
      if evidence['group'] == 'dropped':
        list_dropped.append(evidence)
      if evidence['group'] == 'embedded':
        list_embedded.append(evidence)
      if evidence['group'] == 'contacted':
        list_contacted.append(evidence)
      if evidence['group'] == 'behaviour':
        list_behaviour.append(evidence)

    if list_filenames:
      self.showEvidenceGroup(list_filenames, 'File names')

    if list_dropped:
      self.showEvidenceGroup(list_dropped, 'Dropped')

    if list_embedded:
      self.showEvidenceGroup(list_embedded, 'Embedded')

    if list_contacted:
      self.showEvidenceGroup(list_contacted, 'Contacted')

    if list_behaviour:
      sb_keys=list(self.vt_report.list_sandboxes())
      for key in sb_keys:
        list_sandbox = []
        for evidence in list_behaviour:
          if key == evidence['source']:
            list_sandbox.append(evidence)
        if list_sandbox:
          self.showEvidenceGroup(list_sandbox, key)


  def OnClose(self, form):
    """
    Called when the plugin form is closed
    """
    pass

  def Show(self, title):
    """Creates the form is not created or focuses it if it was"""
    flags = (
      idaapi.PluginForm.WOPN_DP_RIGHT
      | idaapi.PluginForm.WOPN_MENU
      | idaapi.PluginForm.WOPN_PERSIST
    )
    return PluginForm.Show(self,
                           title,
                           options = flags)
