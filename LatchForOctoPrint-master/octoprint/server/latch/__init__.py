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
import re
import latch

from config import *

## LATCH VARIABLES ##
# Imported from config file

api = latch.Latch(app_id, secret_key)

def checkLatch():
  response = api.status(account_id)
  responseData = response.get_data()

  status = re.findall(r"{u'status': u'(.*?)'}",str(responseData))
  if status[0] == "on":
    return True
  else:
    return False