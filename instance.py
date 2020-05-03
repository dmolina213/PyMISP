#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Created on Sep 20, 2016
@author: deralexxx
Script to pull iocs from iSight and push them to MISP
Alexander Jaeger
See CHANGELOG.md for history
"""

import datetime
import email.utils
import hashlib
import hmac
import json
import os
from pymisp import ExpandedPyMISP, MISPEvent, MISPObject
from pymisp import PyMISP, MISPEvent, MISPObject
import requests
import sys
import threading
import time
import urllib.parse
import urllib3

# Read the config file.
import PySight_settings

def get_misp_instance():
    """
    :return: MISP Instance
    :rtype: PyMISP
    """
    print('****hello****in get_misp_instance')
    # Proxy settings are taken from the config file and converted to a dict.
    if PySight_settings.USE_MISP_PROXY:
        misp_proxies = {
            'http': str(PySight_settings.proxy_address),
            'https': str(PySight_settings.proxy_address)
        }
    else:
        misp_proxies = {}

    try:
        # URL of the MISP instance, API key and SSL certificate validation are taken from the config file.
        return ExpandedPyMISP(PySight_settings.misp_url, PySight_settings.misp_key, PySight_settings.misp_verifycert)

        return PyMISP(PySight_settings.misp_url, PySight_settings.misp_key, PySight_settings.misp_verifycert
                     )
    except Exception:
        PySight_settings.logger.error('Unexpected error in MISP init: %s', sys.exc_info())
        return False



misp_instance=get_misp_instance()
print("********getting misp_instance********")
print(misp_instance)

