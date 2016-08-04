#!/usr/bin/env python
#-*- coding: utf-8 -*-

#Copyright (c) 2016 Alvaro Nunez
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
----------------------------------------------------------------------------
                           Latch for OctoPrint
----------------------------------------------------------------------------
"""

## LIBRARIES ##
import re, sys
import latch

from config import *

## LATCH VARIABLES ##
# Imported from config file

api = latch.Latch(app_id, secret_key)

def pairLatch(pairingCode):
  response = api.pair(pairingCode)
  responseData = response.get_data()
  responseError = response.get_error()
  #print responseData
  account_add = re.findall(r"{u'accountId': u'(.*?)'}",str(responseData))
  if responseData:
    print 'Paired service'
    print 'Please, add the following account ID in the config file: ' + chr(27) + "[0;32m" + account_add[0] + chr(27) + "[0m"
  print responseError

def unpairLatch():
  response = api.unpair(account_id)
  responseData = response.get_data()
  responseError = response.get_error()
  print responseData
  print responseError
  print 'Unpaired service'

if (len(sys.argv) > 2):
	if (sys.argv[1] == '-p'):
		pairCode = sys.argv[2]
		pairLatch(pairCode)

if (len(sys.argv) > 1):
	if (sys.argv[1] == '-u'):
		unpairLatch()