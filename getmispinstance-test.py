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

# Import our own iSight report model.
from model.pySightReport import pySightReport

# Suppress insecure HTTPS request warnings.
urllib3.disable_warnings()
#######################
# Process all FireEye iSight reports and convert them to MISP events.
def misp_process_isight_indicators(a_result):
    """
    :param a_result:
    :type a_result:
    """

    # Process each indicator in the JSON message
    for indicator in a_result['message']:
        print('#####in misp process isihht indicators###',indicator)
        PySight_settings.logger.debug('Processing report %s', indicator['reportId'])

        if PySight_settings.use_threading:
            print('####threading####')
            # Use threads to process the indicators
            # First, set the maximum number of threads
            thread_limiter = threading.BoundedSemaphore(value=PySight_settings.number_threads)
            # Define a thread
            t = threading.Thread(target=process_isight_indicator, args=(indicator,))
            # Start the thread
            t.start()
        else:
            # No threading
            process_isight_indicator(indicator)
######################
# Create a new MISP event.
def create_misp_event(misp_instance, isight_report_instance):
    print('######creating misp event:',misp_instance,isight_report_instance)

    # No MISP event for this iSight report ID exists yet.
    # Alas, create a new MISP event.

    # Convert the publication date of the iSight report into a datetime object.
    if isight_report_instance.publishDate:
        date = datetime.datetime.fromtimestamp(isight_report_instance.publishDate)
    else:
        # If iSight doesn't provide a date, use today's date.
        date = datetime.datetime.now(datetime.timezone.utc)

    # Create a MISP event from the FireEye iSight report with the following parameters.
    event = MISPEvent()
    event.distribution = 1  # This community only
    if isight_report_instance.riskRating == 'CRITICAL' or isight_report_instance.riskRating == 'Critical':
        event.threat_level_id = 1  # High
    elif isight_report_instance.riskRating == 'HIGH' or isight_report_instance.riskRating == 'High':
        event.threat_level_id = 1  # High
    elif isight_report_instance.riskRating == 'MEDIUM' or isight_report_instance.riskRating == 'Medium':
        event.threat_level_id = 2  # Medium
    elif isight_report_instance.riskRating == 'LOW' or isight_report_instance.riskRating == 'Low':
        event.threat_level_id = 3  # Low
    else:
        event.threat_level_id = 4  # Unknown
    event.analysis = 2  # Completed
    event.info = "iSIGHT: " + isight_report_instance.title
    event.date = date

    # Push the event to the MISP server.
    print('######push event to MISP server######')
    my_event = misp_instance.add_event(event, pythonify=True)
    PySight_settings.logger.debug('Created MISP event %s for iSight report %s', event, isight_report_instance.reportId)

    # Add default tags to the event.
    misp_instance.tag(my_event, 'basf:classification="internal"')
    #misp_instance.tag(my_event, 'basf:source="iSight"')
    misp_instance.tag(my_event, 'tlp:amber')

    # Use some iSight ThreatScapes for event tagging. Reports can have multiple ThreatScapes.
    if 'Cyber Espionage' in isight_report_instance.ThreatScape:
        # VERIS distinguishes between external, internal or partner actors. This difference is not yet implemented in
        # MISP. External would be most likely.
        #misp_instance.tag(my_event, 'veris:actor:external:motive="Espionage"')
        misp_instance.tag(my_event, 'veris:actor:motive="Espionage"')
    if 'Hacktivism' in isight_report_instance.ThreatScape:
        misp_instance.tag(my_event, 'veris:actor:external:variety="Activist"')
    if 'Critical Infrastructure' in isight_report_instance.ThreatScape:
        misp_instance.tag(my_event, 'basf:technology="OT"')
    if 'Cyber Physical' in isight_report_instance.ThreatScape:
        misp_instance.tag(my_event, 'basf:technology="OT"')
    if 'Cyber Crime' in isight_report_instance.ThreatScape:
        misp_instance.tag(my_event, 'veris:actor:external:variety="Organized crime"')

    # Add the iSight report ID and web link as attributes.
    if isight_report_instance.reportId:
        misp_instance.add_attribute(my_event, {'category': 'External analysis', 'type': 'text', 'to_ids': False,
                                               'value': isight_report_instance.reportId}, pythonify=True)
    if isight_report_instance.webLink:
        misp_instance.add_attribute(my_event, {'category': 'External analysis', 'type': 'link', 'to_ids': False,
                                               'value': isight_report_instance.webLink}, pythonify=True)

    # Put the ThreatScape into an Attribution attribute, but disable correlation.
    if isight_report_instance.ThreatScape:
        misp_instance.add_attribute(my_event, {'category': 'Attribution', 'type': 'text', 'to_ids': False,
                                               'value': isight_report_instance.ThreatScape,
                                               'disable_correlation': True}, pythonify=True)

    # Add specific attributes from this iSight report.
    update_misp_event(misp_instance, my_event, isight_report_instance)

######################
# Process one FireEye iSight report and convert it into a MISP events.
def process_isight_indicator(a_json):
    """
    Create a pySightAlert instance of the json and make all the mappings
    :param a_json:
    :type a_json:
    """

    try:
        # Get a MISP instance per thread
        this_misp_instance = get_misp_instance()
        print('####this misp instance:',this_misp_instance)
        # Without a MISP instance this does not make sense
        if this_misp_instance is False:
            raise ValueError("No MISP instance found.")

        # Acquire a semaphore (decrease the counter in the semaphore).
        if PySight_settings.use_threading:
            thread_limiter.acquire()
        # PySight_settings.logger.debug("max number %s current number: ", thread_limiter._initial_value, )

        # Parse the FireEye iSight report
        isight_report_instance = pySightReport(a_json)

        # If in DEBUG mode, write the iSight reports to a file.
        if PySight_settings.debug_mode:
            # Create the "reports" subdirectory for storing iSight reports, if it doesn't exist already.
            if not os.path.exists("reports"):
                os.makedirs("reports")
            f = open("reports/" + isight_report_instance.reportId, 'a')
            # Write the iSight report into the "reports" subdirectory.
            f.write(json.dumps(a_json, sort_keys=True, indent=4, separators=(',', ': ')))
            f.close()

        # Check whether we already have an event for this reportID.
        PySight_settings.logger.debug('Checking for existing event with report ID %s', isight_report_instance.reportId)
        event_id = misp_check_for_previous_event(this_misp_instance, isight_report_instance)

        if not event_id:
            # Create a new MISP event
            PySight_settings.logger.debug('No event found for report ID %s -- will create a new one',
                                          isight_report_instance.reportId)
            create_misp_event(this_misp_instance, isight_report_instance)
        else:
            # Add the data to the found event
            event = this_misp_instance.get_event(event_id, pythonify=True)
            update_misp_event(this_misp_instance, event, isight_report_instance)

        # Reset the iSight report instance when done.
        isight_report_instance = None

        # Release the semaphore (increase the counter in the semaphore).
        if PySight_settings.use_threading:
            thread_limiter.release()

    except AttributeError as e_AttributeError:
        sys, traceback = error_handling(e_AttributeError, a_string="Attribute Error")
        return False
    except TypeError as e_TypeError:
        sys, traceback = error_handling(e_TypeError, a_string="Type Error:")
        return False
    except Exception as e_Exception:
        sys, traceback = error_handling(e_Exception, a_string="General Error:")
        return False    

##################
# Error handling function.
def error_handling(e, a_string):
    """
    :param e:
    :type e:
    :param a_string:
    :type a_string:
    :return:
    :rtype:
    """
    if hasattr(e, 'message'):
        PySight_settings.logger.error('%s %s', a_string, e.message)
    import traceback
    PySight_settings.logger.debug('1 %s', e.__doc__)
    PySight_settings.logger.debug('2 %s', sys.exc_info())
    PySight_settings.logger.debug('3 %s', sys.exc_info()[0])
    PySight_settings.logger.debug('4 %s', sys.exc_info()[1])
    #PySight_settings.logger.debug('5 %s', sys.exc_info()[2], 'Sorry I mean line...',
    #                              traceback.tb_lineno(sys.exc_info()[2]))
    ex_type, ex, tb = sys.exc_info()
    PySight_settings.logger.debug('6 %s', traceback.print_tb(tb))
    return sys, traceback
######################################
def isight_search_indicators(base_url, public_key, private_key, hours):
    # Convert hours to seconds and subtract them from the current time
    PySight_settings.logger.debug('isight_search_indicators')
    since = int(time.time()) - hours * 60 * 60

    # Limit the returned data to that published since this Epoch datetime and the present time.
    # Therefore, add the 'since' parameter as a query string.
    params = {
        'since': since
    }
    search_query = '/view/indicators?' + urllib.parse.urlencode(params)
    print('******search query is:', search_query)

    # Retrieve indicators and warning data since the specified date and time.
    return isight_prepare_data_request(base_url, search_query, public_key, private_key)
   # return search_query
# Prepare the request to the FireEye iSight API.
def isight_prepare_data_request(a_url, a_query, a_pub_key, a_prv_key):
    """
    :param a_url:
    :type a_url:
    :param a_query:
    :type a_query:
    :param a_pub_key:
    :type a_pub_key:
    :param a_prv_key:
    :type a_prv_key:
    :return:
    :rtype:
    """
    header = set_header(a_prv_key, a_pub_key, a_query)
    result = isight_load_data(a_url, a_query, header)
    print('***header:',header,'****')
    print('***result:',result,'****')
    if not result:
        PySight_settings.logger.error('*****Something went wrong when retrieving indicators from the FireEye iSight API***')
        PySight_settings.logger.debug('***Something went wrong when retrieving indicators from the FireEye iSight API**')
        print('***Something went wrong when retrieving indicators from the FireEye iSight API**')
        return False
    else:
        return result
# Define the header for the HTTP requests to the iSight API.
def set_header(a_prv_key, a_pub_key, a_query):
    """
    :param a_prv_key:
    :type a_prv_key:
    :param a_pub_key:
    :type a_pub_key:
    :param a_query:
    :type a_query:
    :return: Header for iSight search
    :rtype:
    """
    print('****set_header****')
    # Prepare the data to calculate the X-Auth-Hash.
    accept_version = '2.5'
    output_format = 'application/json'
    time_stamp = email.utils.formatdate(localtime=True)
    string_to_hash = a_query + accept_version + output_format + time_stamp

    # Convert the authentication information from UTF-8 encoding to a bytes object
    message = bytes(string_to_hash, 'utf-8')
    secret = bytes(a_prv_key, 'utf-8')

    # Hash the authentication information
    hashed = hmac.new(secret, message, hashlib.sha256)
    #dictionary
    header = {
        'X-Auth': a_pub_key,
        'X-Auth-Hash': hashed.hexdigest(),
        'Accept': output_format,
        'Accept-Version': accept_version,
        'Date': time_stamp
    }
    PySight_settings.logger.debug('***header**',header)
    print('*****header is:',header)
    return header
###################
def isight_load_data(a_url, a_query, a_header):
    """
    :param a_url:
    :type a_url:
    :param a_query:
    :type a_query:
    :param a_header:
    :type a_header:
    :return:
    :rtype:
    """

    # This is the URL for the iSight API query
    url_to_load = a_url + a_query
    print('######isight_load_data,url_to_load:',url_to_load)

    # Set the proxy if specified
    if PySight_settings.USE_ISIGHT_PROXY:
        isight_proxies = {
            'http': PySight_settings.proxy_address,
            'https': PySight_settings.proxy_address
        }
        PySight_settings.logger.debug('Connecting to FireEye iSight via proxy %s', PySight_settings.proxy_address)
    else:
        isight_proxies = {}
        PySight_settings.logger.debug('Connecting directly to FireEye iSight without a proxy')
                                      

    PySight_settings.logger.debug('FireEye iSight request URL: %s', url_to_load)
    PySight_settings.logger.debug('FireEye iSight request header: %s', a_header)

    try:
        r = requests.get(url_to_load, headers=a_header, proxies=isight_proxies, verify=False)
    except urllib.error.HTTPError as e:
        PySight_settings.logger.error('Urllib HTTP error code: %s', e.code)
        PySight_settings.logger.error('Urllib HTTP error message: %s', e.read())
    except requests.exceptions.ChunkedEncodingError as e:
        PySight_settings.logger.error('Error when connecting to the FireEye iSight API: %s', e)
        return False

    if r.status_code == 204:
        PySight_settings.logger.warning('No result found for search')
        return False
    elif r.status_code == 404:
        PySight_settings.logger.error('%s: check the FireEye iSight API URL', r.reason)
        PySight_settings.logger.debug('%s', r.text)
        return False
    elif r.status_code != 200:
        PySight_settings.logger.error('Request not successful: %s', r.text)
        return False

    return_data_cleaned = r.text.replace('\n', '')

    json_return_data_cleaned = json.loads(return_data_cleaned)
    PySight_settings.logger.debug('Number of indicators returned: %s', len(json_return_data_cleaned['message']))

    if not json_return_data_cleaned['success']:
        PySight_settings.logger.error('Error with the FireEye iSight API connection %s',
                                      json_return_data_cleaned['message']['description'])
        PySight_settings.logger.debug(json_return_data_cleaned)
        return False
    else:
        # For debugging purposes, write the returned IOCs to a file
        if PySight_settings.debug_mode:
            timestring = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
            if not os.path.exists('debug'):
                os.makedirs('debug')
            f = open('debug/' + timestring, 'w')
            f.write(json.dumps(json_return_data_cleaned, sort_keys=True, indent=6, separators=(',', ': ')))
            f.close()

        return json_return_data_cleaned

##################

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
        return ExpandedPyMISP(PySight_settings.misp_url, PySight_settings.misp_key, PySight_settings.misp_verifycert,proxies=misp_proxies)
                             
       # return PyMISP(PySight_settings.misp_url, PySight_settings.misp_key, PySight_settings.misp_verifycert
                    
    except Exception:
        PySight_settings.logger.error('Unexpected error in MISP init: %s', sys.exc_info())
        return False
############################Main##############
print('### Retrieve FireEye iSight indicators of the last x hours###')
result = isight_search_indicators(PySight_settings.isight_url, PySight_settings.isight_pub_key,
                                      PySight_settings.isight_priv_key, PySight_settings.isight_last_hours)
print('*********',result,'********')

if result is False:
        PySight_settings.logger.warning('No indicators available from FireEye iSight')
else:
        misp_process_isight_indicators(result)

misp_instance=get_misp_instance()
print("********getting misp_instance********")
print(misp_instance)

