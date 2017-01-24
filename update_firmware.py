# -*- coding: utf-8 -*-
#!/usr/bin/python

# usage: python ./update_firmware.py –c multi-server-config
# prerequite: 
# 1)FW 2.0(3d) for C220 and C240 downloaded on build server /var/www/cobbler/pub
# 2) ACL open between OOB and infra-001 port 80 and 443
# 3) Create config file similar to the sample multi-server config
   
import os
import sys
import signal
from time import *
#import urllib2
from urllib2 import Request, urlopen, URLError, HTTPError
from httplib import BadStatusLine
import optparse
from xml.dom.minidom import *

# SSL Passthrough Fix
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

try:
  import multiprocessing, Queue, threading
except ImportError:
  print '[Error]: Python multiprocessing module not available. Please install it before trying again.'
  sys.exit(0)
import logging
import logging.handlers
try:
  import ssl
except ImportError:
  global supportSsl
  print '[Error]: no ssl support on this host. https will not work.'
  supportSsl = False

global supportCrypto
supportCrypto = True
global supportEncoding
supportEncoding = True

try:  
	import getpass
except ImportError:
	print '[Information] Needed packages "getpass" not available. Cannot support password encryption feature.'
	supportCrypto = False

try:
	from Crypto.PublicKey import RSA
except ImportError:
	print '[Information] Needed packages "Crypto.PublicKey.RSA" not available. Cannot support password encryption feature.'
	supportCrypto = False

try:	
	from Crypto import Random
except ImportError:
	print '[Information] Needed packages "Crypto.Random" not available. Cannot support password encryption feature.'
	supportCrypto = False

try:
	from xml.sax.saxutils import quoteattr
except ImportError:
	print '[Information] Needed packages "xml.sax.saxutils.quoteattr" not available. Cannot support password encryption feature.'
	supportEncoding = False

#Version
version="1.1"

# Global variable
cimcUpdateDict = { }
supportSsl = True
DEFAULT_LEVEL = logging.DEBUG
logFormatter = logging.Formatter("%(levelname)s: %(asctime)s - %(name)s - %(process)s - %(message)s")



# Function handle the key board interrupt
def HuuKeyboardInterruptHandler(signal, frame):
  print '[Critical]: Pressed ctrl c'
  sys.exit(0)


class HuuLogQueueHandler(logging.Handler):
  """
  This is a logging handler which sends events to a multiprocessing queue.
  """

  def __init__(self, queue):
    """
    Initialise an instance, using the passed queue.
    """
    logging.Handler.__init__(self)
    self.queue = queue
							        
  def emit(self, logData):
    """
    Writes the LogData to the queue.
    """
    try:
      self.queue.put(logData)
    except:
      print '[Error] exiting'
      sys.exit(0)


class HuuLoggerThread(threading.Thread):
  """Thread to write subprocesses log records to main process log

     This thread reads the records written by subprocesses and writes them to
     the handlers defined in the main process's handlers.
  """

  def __init__(self, queue, logger):
    threading.Thread.__init__(self)
    self.queue = queue
    self.logger = logger
    self.daemon = True

  def run(self):
    """read from the queue and write to the log handlers
    """

    while True:
      try:
        record = self.queue.get()
        if record is None:
          break
        self.logger.handle(record)
      except (KeyboardInterrupt, SystemExit):
        raise
      except EOFError:
        break
      except KeyError:
        break
      except IOError:
        break
      except:
        traceback.print_exc(file=sys.stderr)


def HuuProcessLoggerConfigurer(logQueue):
  processName = multiprocessing.current_process().name
  pLogger = logging.getLogger(processName)

  # The only handler desired is the HuuLogQueueHandler.  If any others
  # exist, remove them. In this case, on Unix and Linux the StreamHandler
  # will be inherited.
  for handler in pLogger.handlers:
    logger.removeHandler(handler)

  # Add the required handler
  logQueueHandler = HuuLogQueueHandler(logQueue)
  logQueueHandler.setFormatter(logFormatter)
  pLogger.addHandler(logQueueHandler)
  pLogger.setLevel(DEFAULT_LEVEL)
  return pLogger


# This function only useful in case where an element node has
# multiple attributes and this function searches for specific
# attribute among them
def HuuXmlGetAttributeValue(logger, xmlString, elementTag, *args):
  """
  Call this function retrieve attribute values corresponding to a tag.
  """
  attrValueDict = { }

  # Check if the XML string is not proper due to parser error in the response
  if ("XML PARSING ERROR" in xmlString):
    logger.error('Not able to parse this string.')
    attrValueDict['response'] = 'yes'
    attrValueDict['errorCode'] = '-1'
    attrValueDict['errorDescr'] = 'XML PARSING ERROR'
    return attrValueDict
 
  try:
    xmlDoc = parseString(xmlString)
  except:
    logger.error('Failed to parse.');
    return None

  if (xmlDoc == None):
    return None

  elementsList = xmlDoc.getElementsByTagName(elementTag)
  if (elementsList == None):
    return None

  for attribute in args:
    attrValueDict[attribute] = None
    for element in elementsList:
      if (element.hasAttribute(attribute)):
        attrValueDict[attribute] = element.getAttribute(attribute)

  return attrValueDict



class HuuUpdateState:
  HUU_UPDATE_LOGIN_STATE_LOGGED_IN = 1
  HUU_UPDATE_LOGIN_STATE_LOGGED_OUT = 2
  HUU_UPDATE_LOGIN_STATE_KEEPALIVE_SENT = 4
  HUU_UPDATE_LOGIN_STATE_KEEPALIVE_FAILED = 8
  HUU_UPDATE_LOGIN_STATE_KEEPALIVE_RCVD = 16

  HUU_UPDATE_STATE_INITIALIZED = 1
  HUU_UPDATE_STATE_REQ_FIRMWARE_STATE = 2
  HUU_UPDATE_STATE_RCVD_FIRMWARE_STATE = 3
  HUU_UPDATE_STATE_FAILED_FIRMWARE_STATE = 4
  HUU_UPDATE_STATE_SEND_UPDATE_REQ = 5
  HUU_UPDATE_STATE_RCVD_UPDATE_RESPONSE = 6
  HUU_UPDATE_STATE_FAILED_UPDATE_RESPONSE = 7
  HUU_UPDATE_STATE_SEND_STATUS_REQ = 8
  HUU_UPDATE_STATE_RCVD_STATUS_RESPONSE = 9
  HUU_UPDATE_STATE_FAILED_STATUS_RESPONSE = 10
  HUU_UPDATE_STATE_SEND_UPDATER_REQ = 11
  HUU_UPDATE_STATE_RCVD_UPDATER_RESPONSE = 12
  HUU_UPDATE_STATE_FAILED_UPDATER_RESPONSE = 13
  HUU_UPDATE_STATE_UPDATE_SUCCESSFULL = 14
  HUU_UPDATE_STATE_UPDATE_FAILED = 15
  HUU_UPDATE_STATE_SEND_UPDATE_DETAILS_REQ = 16
  HUU_UPDATE_STATE_RCVD_UPDATE_DETAILS_RESPONSE = 17
  HUU_UPDATE_STATE_FAILED_UPDATE_DETAILS_RESPONSE = 18
  HUU_UPDATE_STATE_UPDATE_NOT_SUPPORTED = 19

  HUU_UPDATE_TASK_LOGIN = 1
  HUU_UPDATE_TASK_KEEPALIVE = 2
  HUU_UPDATE_TASK_LOGOUT = 3
  HUU_UPDATE_TASK_REQ_FIRMWARE = 4
  HUU_UPDATE_TASK_UPDATE_FIRMWARE = 5
  HUU_UPDATE_TASK_REQ_STATUS = 6
  HUU_UPDATE_TASK_REQ_UPDATER = 7
  HUU_UPDATE_TASK_REQ_UPDATE_DETAILS = 8
  HUU_UPDATE_TASK_NONE = 9
  HUU_CATALOG_STATE_DONE = 200

class HuuUpdateHost:
  # class variables
  remoteShareIp = None
  shareType = None
  shareDirectory = None
  remoteShareUser = None
  remoteSharePassword = None
  updateTimeout = '60'
  updateStopOnError = 'no'
  updateVerify = 'no'
  updateComponent = 'all'
  noSsl = False
  cimcSecureBoot = None
  rebootCimc = 'no'
  dispComponentList = False
  flagCimc = False

  def __init__(self, cimcIp, user, password, image):
    self.cimcIpAddress = cimcIp
    self.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT
    self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_INITIALIZED
    self.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_NONE
    self.lastTaskStatus = None
    self.delayStartTime = None
    self.delayInterval = 60
    self.port = 443
    self.username = user
    self.password = password
    self.updateImageFile = image
    self.huuHostLoggedIn = False
    self.cookie = None
    self.priv = None
    self.refreshPeriod = None
    self.loginRetryCount = 0
    self.loginFailedCount = 0
    self.loginRefreshPeriod = None
    self.lastLoginTime = None
    self.getFirmwareStateRetryCount = 0
    self.getUpdateDetailsRetryCount = 0
    self.updateRetryCount = 0
    self.updateFailedCount = 0
    self.updateStartTime = None
    self.updateTimeOutValue = 7200     # 60 mins is the timeout for firmware update
    self.huuUpdateInProgress = False
    self.updateStatusRetryCount = 0
    self.updateFailureCause = None
    self.updateCompleted = False
    self.cdromAdded = False
    self.uefiboot = False           #  Disabled 
    self.uefifeature = True         # Feature is present on the box.

  def Uri(self):
    global supportSsl

    if (supportSsl == True and self.noSsl == False):
        return ('https://%s:%s' %(self.cimcIpAddress, str(self.port)))
#    return ("%s://%s%s" % (("https", "http")[self.noSsl == True], self.name, (":" + str(self.port),"")[(((self.noSsl == False) and (self.port == 80)) or ((self.noSsl == True) and (self.port == 443)))]))
    else:
      return ("http://%s" % (self.cimcIpAddress))

  def HuuUpdateLogin(self, logger):
    if (self.cimcIpAddress == None):
      logger.error('Hostname/IP was not specified')
      self.updateFailureCause = 'CIMC IP address not specified'
      self.lastTaskRetriable = False
      return

    logger.info('Initiating Login to CIMC ' + self.cimcIpAddress)
    if (self.username == None):
      logger.error('Username not specified for CIMC (%s). Can not proceed.' %(self.cimcIpAddress))
      self.lastTaskRetriable = False
      self.updateFailureCause = 'CIMC login user name not provided'
      return

    if (self.password == None):
      logger.error('Password not specified for CIMC (%s). Can not proceed.' %(self.cimcIpAddress))
      self.lastTaskRetriable = False
      self.updateFailureCause = 'CIMC login user password not provided'
      return

    self.cookie = ""
    responseData = self.AaaLogin(logger)

    if (responseData == None):
      logger.error('Login to CIMC (%s) failed. No response received from CIMC' %(self.cimcIpAddress))
      self.loginFailedCount += 1
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC login failed.'
      return

    # Process the XML response
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'aaaLogin', 'response', 'outCookie',
		'outPriv', 'outRefreshPeriod', 'errorCode', 'errorDescr')
    if (responseDict == None):
      logger.debug('Unable to process the AaaLogin response (' + responseData + ') data')
      self.loginFailedCount += 1
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC login failed.'
      return

    if (responseDict['response'] == None):
      self.loginFailedCount += 1
      logger.error('AaaLogin response is not valid from CIMC (%s)' %(self.cimcIpAddress))
      del responseDict
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC login failed.'
      return

    if (responseDict['response'] != "yes"):
      self.loginFailedCount += 1
      logger.error('AaaLogin response is not valid from CIMC (%s)' %(self.cimcIpAddress))
      del responseDict
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC login failed.'
      return

    if (responseDict['errorCode'] != None):
      logger.error('Login error code: %s from CIMC (%s).' %(str(responseDict['errorCode']), self.cimcIpAddress))
      self.updateFailureCause = 'CIMC login failed.'
      if (responseDict['errorDescr'] != None):
        logger.error('Login failure reason for CIMC (%s),  errorDescr: %s.' %(self.cimcIpAddress,str(responseDict['errorDescr'])))
        self.updateFailureCause = responseDict['errorDescr']

      self.loginFailedCount += 1
      del responseDict
      self.lastTaskRetriable = False
      return

    if (responseDict['outCookie'] == None or responseDict['outRefreshPeriod'] == None):
      logger.error('Unable to get login cookie from CIMC (%s), login failed.' %(self.cimcIpAddress))
      self.loginFailedCount += 1
      del responseDict
      self.lastTaskRetriable = False
      self.updateFailureCause = 'CIMC login failed'
      return

    if (responseDict['outPriv'] != "admin"):
      logger.error('User - %s do not have admin priviledge to update firmware for CIMC (%s).' %(self.username, self.cimcIpAddress));
      self.loginFailedCount += 1
      del responseDict
      self.lastTaskRetriable = False
      self.updateFailureCause = 'CIMC login user do not have admin previledge to update firmware'
      return

    self.cookie = responseDict['outCookie']
    self.lastLoginTime = time()
    self.huuHostLoggedIn = True
    if (responseDict['outPriv'] != None):
      self.priv = responseDict['outPriv']
    self.refreshPeriod = responseDict['outRefreshPeriod']
    self.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_IN 
    logger.info('Successfully logged in to CIMC ' + self.cimcIpAddress)
    self.updateRetryCount = 0
    del responseDict
    self.lastTaskRetriable = True
    if self.dispComponentList == True:
	self.displayComponentList(logger)
        self.huuUpdateState = HuuUpdateState.HUU_CATALOG_STATE_DONE

    logger.debug("Reboot CIMC =" + self.rebootCimc) 
    if self.rebootCimc == "yes":
     self.rebootCimcReq(logger)
     logger.debug("Calling CIMC Reboot")
     self.rebootCimc='no'	 
     self.HuuUpdateLogin(logger);
    else:
     logger.debug("Not Calling CIMC Reboot")

    return

  def rebootCimcReq(self, logger ):
    
    dclRequest = """<configResolveClass cookie='cookieValue' inHierarchical='true' classId='huuFirmwareCatalog'/>"""
    dclRequest = """<configConfMo cookie='cookieValue' dn='sys/rack-unit-1' inHierarchical='false'><inConfig><computeRackUnit dn='sys/rack-unit-1' adminPower='bmc-reset-immediate'/></inConfig></configConfMo>"""

    dclRequest = dclRequest.replace('cookieValue', self.cookie)

    logger.debug('Display Component List request data==>' + dclRequest)
    
    uri = self.Uri() + '/nuova'
    
    logger.debug('dclRequest uri data==>' + uri)
    
    # Send the XML request over http/https
    
    req = Request(url=uri, data=dclRequest)
    try:
      urlId = urlopen(req, timeout = 180)
    except HTTPError, e:
      logger.error('The CIMC (%s) couldn\'t fulfill the request. Error code: %s' %(self.cimcIpAddress, e.code))
    except URLError, e:
      logger.error('We failed to reach CIMC (%s). Reason: %s ' %(self.cimcIpAddress, e.reason))
    except BadStatusLine:
      logger.error('CIMC (%s) returning empty page. Check the XML support status of CIMC.' %(self.cimcIpAddress))
    except:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
    else:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
      
    logger.debug('Cisco IMC Reboot Sent.')

    sleep(60 * 3)      	

    return None	

  def displayComponentList(self, logger ):
    
    dclRequest = """<configResolveClass cookie='cookieValue' inHierarchical='true' classId='huuFirmwareCatalog'/>"""

    dclRequest = dclRequest.replace('cookieValue', self.cookie)

    logger.debug('Display Component List request data==>' + dclRequest)
    
    uri = self.Uri() + '/nuova'
    
    logger.debug('dclRequest uri data==>' + uri)
    
    # Send the XML request over http/https
    
    req = Request(url=uri, data=dclRequest)
    try:
      urlId = urlopen(req, timeout = 180)
    except HTTPError, e:
      logger.error('The CIMC (%s) couldn\'t fulfill the request. Error code: %s' %(self.cimcIpAddress, e.code))
      return None
    except URLError, e:
      logger.error('We failed to reach CIMC (%s). Reason: %s ' %(self.cimcIpAddress, e.reason))
      return None
    except BadStatusLine:
      logger.error('CIMC (%s) returning empty page. Check the XML support status of CIMC.' %(self.cimcIpAddress))
      return None
    except:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
      return None
    else:
      rsp = urlId.read()
      if (rsp == None):
        logger.error('configMoRequest response empty from CIMC (' + self.cimcIpAddress + ')')
        return None
    
      logger.debug('CIMC (' + self.cimcIpAddress + ') configMoRequest response==>' + rsp)

    responseDict =HuuXmlGetAttributeValue(logger, rsp, 'configResolveClass', 'response','errorCode', 'errorDescr')
      
    if (responseDict == None):
      logger.debug('Unable to process the SetBootOrder response (' + rsp + ') data')
      return None

    if (responseDict['response'] == None):
      logger.error('Get Catalog response is not valid from CIMC (%s)' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['response'] != "yes"):
      logger.error('Get Catalog response is not valid from CIMC (%s). Response is None' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['errorCode'] != None):
      logger.error('Get Catalog error code: %s from CIMC (%s). ' %(str(responseDict['errorCode']), self.cimcIpAddress))
      if (responseDict['errorDescr'] != None):
        logger.error('Get Catalog failure reason for CIMC (%s),  errorDescr: %s.' %(self.cimcIpAddress,str(responseDict['errorDescr'])))
        self.updateFailureCause = responseDict['errorDescr']

      del responseDict
      self.cdromAdded = False      
      return None
    
    logger.debug('Catalog Response [ %s ] ' %(rsp) )
    print "================================="
    print "            CATALOG "
    print "================================="
    try:
      xmlDoc = parseString(rsp)
    except:
      logger.error('Failed to parse.');
      return None

    if (xmlDoc == None):
      return None

    elementsList = xmlDoc.getElementsByTagName("huuFirmwareCatalogComponent")
    if (elementsList == None):
      return None


    for element in elementsList:
        component = element.getAttribute("componentName")
	description = element.getAttribute("description")
	print 'Component = [ %s ] \t\t Description = [ %s ]' %(component,description)
    

    return None	

  def HuuUpdateKeepAlive(self, logger):
    responseData = self.AaaKeepAlive(logger)

    if (responseData == None):
      logger.error('KeepAlive to CIMC (%s) failed. No response received from CIMC' %(self.cimcIpAddress))
      self.loginState = self.loginState | HuuUpdateState.HUU_UPDATE_LOGIN_STATE_KEEPALIVE_FAILED 
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC relogin failure'
      return

    # Process the XML response
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'aaaKeepAlive', 'response', 'errorCode', 'errorDescr')
    if (responseDict == None):
      logger.error('Unable to process CIMC (%s) KeepAlive response: %s' %(self.cimcIpAddress,responseData))
      self.loginState = self.loginState | HuuUpdateState.HUU_UPDATE_LOGIN_STATE_KEEPALIVE_FAILED 
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC relogin failure'
      return

    if (responseDict['response'] != "yes"):
      self.loginFailedCount += 1
      logger.error('KeepAlive response is not valid from CIMC (%s)' %(self.cimcIpAddress))
      self.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT | HuuUpdateState.HUU_UPDATE_LOGIN_STATE_KEEPALIVE_RCVD
      del responseDict
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC relogin failure'
      return

    if (responseDict['errorCode'] != None):
      logger.error('KeepAlive error code: %s from CIMC (%s).' %(str(responseDict['errorCode']), self.cimcIpAddress))
      if (responseDict['errorDescr'] != None):
        logger.error('KeepAlive failure reason for CIMC (%s),  errorDescr: %s.' %(self.cimcIpAddress,str(responseDict['errorDescr'])))

      del responseDict
      self.lastTaskRetriable = False
      self.updateFailureCause = responseDict['errorDescr']
      return

    self.loginState = (self.loginState & ~HuuUpdateState.HUU_UPDATE_LOGIN_STATE_KEEPALIVE_FAILED) | HuuUpdateState.HUU_UPDATE_LOGIN_STATE_KEEPALIVE_RCVD
    del responseDict
    self.lastTaskRetriable = False
    return


  def HuuUpdateLogout(self, logger):
    responseData = self.AaaLogout(logger)

    if (responseData == None):
      logger.error('Logout from CIMC (%s) failed. No response received from CIMC' %(self.cimcIpAddress))
      self.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT
      self.lastTaskRetriable = True
      return

    # Process the XML response
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'aaaLogout', 'response', 'outStatus')
    if (responseDict == None):
      logger.error('Unable to process the CIMC (%s) Logout response: %s' %(self.cimcIpAddress, responseData))
      self.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT
      self.lastTaskRetriable = True
      return

    if (responseDict['response'] != "yes"):
      logger.error('Logout response is not valid from CIMC (%s)' %(self.cimcIpAddress))
      self.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT
      del responseDict
      self.lastTaskRetriable = True
      return

    self.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT
    del responseDict
    self.lastTaskRetriable = True
    return


  def HuuUpdateCheckFirmware(self, logger):
    responseData = self.ConfigResolveClass(logger, 'huuController')

    if (responseData == None):
      logger.error('Did not get response for check firmware request for CIMC (' + self.cimcIpAddress + ')')
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_FIRMWARE_STATE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      return

    if ("XML PARSING ERROR" in responseData):
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_FIRMWARE_STATE
      self.lastTaskRetriable = False
      self.updateFailureCause = 'CIMC do not support this request'
      return

    # Process the XML response
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'configResolveClass', 'response',
	  'errorCode', 'errorDescr')
    if (responseDict == None):
      logger.error('Unable to process CIMC (%s) check firmware response: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_FIRMWARE_STATE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC do not support this request'
      return

    if (responseDict['response'] != "yes"):
      logger.error('Check firmware response from CIMC (%s) is not valid. Rsp: %s' %(self.cimcIpAddress,responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_FIRMWARE_STATE
      del responseDict
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC do not support this request'
      return

    if (responseDict['errorCode'] != None):
      logger.error('Check firmware CIMC (%s) error code: %s' %(self.cimcIpAddress, str(responseDict['errorCode'])))
      self.updateFailureCause = 'CIMC do not support this request'
      if (responseDict['errorDescr'] != None):
        logger.error('Check firmware CIMC (%s) failure reason, errorDescr: %s' %(self.cimcIpAddress, str(responseDict['errorDescr'])))
        self.updateFailureCause = responseDict['errorDescr']

      self.loginFailedCount += 1
      del responseDict
      self.lastTaskRetriable = False
      return

    del responseDict

    # Process the remaining XML data
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'huuController', 'description')
    if (responseDict == None):
      logger.error('Check firmware response is not valid from CIMC (%s). Rsp: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_FIRMWARE_STATE
      del responseDict
      self.lastTaskRetriable = False
      self.updateFailureCause = 'CIMC do not support this request'
      return
    if (responseDict['description'] != 'Host Upgrade Utility (HUU)'):
      logger.error('Check firmware response is not valid from CIMC (%s). Rsp: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_FIRMWARE_STATE
      del responseDict
      self.lastTaskRetriable = False
      self.updateFailureCause = 'CIMC do not support this request'
      return

    del responseDict

    self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_RCVD_FIRMWARE_STATE
    self.lastTaskRetriable = True


  def HuuUpdateSendFirmwareUpdate(self, logger):
    responseData = self.ConfigConfMo(logger)

    if (responseData == None):
      logger.error('Did not get response for firmware update request for CIMC (' + self.cimcIpAddress + ')')
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_RESPONSE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      return

    # Process the XML response
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'configConfMo', 'response',
	  'errorCode', 'errorDescr')
    if (responseDict == None):
      logger.error('Unable to process the update request response from CIMC (%s), rsp: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_RESPONSE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      return

    if (responseDict['response'] != "yes"):
      logger.error('Firmware update request response is not valid from CIMC (%s). Rsp: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_RESPONSE
      del responseDict
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      return

    if (responseDict['errorCode'] != None):
      logger.error('CIMC (%s) Firmware Update request error code: %s' %(self.cimcIpAddress, str(responseDict['errorCode'])))
      self.updateFailureCause = 'CIMC do not support this request'
      if (responseDict['errorDescr'] != None):
        logger.error('CIMC (%s) Firmware update request failure reason, errorDescr: %s' %(self.cimcIpAddress, str(responseDict['errorDescr'])))
        self.updateFailureCause = responseDict['errorDescr']

      self.loginFailedCount += 1
      del responseDict
      self.lastTaskRetriable = False
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_RESPONSE
      return

    del responseDict

    # Process the remaining XML data
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'huuFirmwareUpdater', 'adminState')
    if (responseDict == None):
      logger.error('Unable to process the update request response from CIMC (%s), rsp: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_RESPONSE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      return
    if (responseDict['adminState'] != 'triggered'):
      logger.error('CIMC (%s) Firmware update request response is not valid. Rsp: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_RESPONSE
      del responseDict
      self.lastTaskRetriable = False
      self.updateFailureCause = 'CIMC could not initiate firmware update'
      return

    del responseDict

    self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_RCVD_UPDATE_RESPONSE
    self.lastTaskRetriable = True


  def HuuUpdateSendUpdateStatus(self, logger):
#    responseData = self.ConfigResolveClass(logger, 'huuUpdateComponentStatus')
    responseData = self.ConfigResolveClass(logger, 'huuFirmwareUpdateStatus')
    
    filename = self.cimcIpAddress + '_LogFile'
    f = open(filename, 'w')
    if (responseData == None):
      logger.error('Did not get response for update status request from CIMC (' + self.cimcIpAddress + ')')
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_STATUS_RESPONSE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      return

    f.write(responseData)
    # Process the XML response
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'configResolveClass', 'response', 'errorCode', 'errorDescr')
    if (responseDict == None):
      logger.error('Unable to process CIMC (%s) update status response: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_STATUS_RESPONSE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      return

    if (responseDict['response'] != "yes"):
      logger.error('Update status response is not valid from CIMC (%s). Rsp: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_STATUS_RESPONSE
      del responseDict
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      return

    if (responseDict['errorCode'] != None):
      if (responseDict['errorDescr'] != None):
        if ("Authorization required" in str(responseDict['errorDescr'])):
          self.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT
          logger.error('Login timed out for CIMC (%s). Rsp: %s' %(self.cimcIpAddress, responseData))
          self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATER_RESPONSE
          del responseDict
          self.lastTaskRetriable = True
          self.updateFailureCause = 'CIMC unresponsive'
          self.updateCompleted = False
          return
      else:
        logger.debug('Ignore error for CIMC (%s). Rsp: %s' %(self.cimcIpAddress, responseData))

    del responseDict
    self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_RCVD_STATUS_RESPONSE

    # Process the remaining XML data
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'huuFirmwareUpdateStatus',
		'overallStatus', 'updateStartTime', 'updateEndTime')
    if (responseDict == None):
      logger.info('HUU image booting. Update yet to start for CIMC (%s).' %(self.cimcIpAddress))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_RCVD_STATUS_RESPONSE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'Firmware update failed'
      if (responseDict['overallStatus'] != None):
        logger.debug('CIMC (%s) update status: %s' %(self.cimcIpAddress, str(responseDict['overallStatus'])))
      del responseDict
      return
    if (responseDict['updateStartTime'] == None and self.updateCompleted == False):
      logger.info('HUU image booting. Update yet to start for CIMC (%s).' %(self.cimcIpAddress))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_RCVD_STATUS_RESPONSE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'Firmware update failed'
      if (responseDict['overallStatus'] != None):
        logger.debug('CIMC (%s) update status: %s' %(self.cimcIpAddress, str(responseDict['overallStatus'])))
      del responseDict
      return

    if (responseDict['updateStartTime'] != None):
      if (responseDict['updateStartTime'] == 'NA'):
        logger.error('Firmware Update did not start for CIMC (%s). Rsp: %s' %(self.cimcIpAddress, responseData))
        self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_STATUS_RESPONSE
        self.lastTaskRetriable = True
        self.updateFailureCause = 'Firmware update did not start'
        if (responseDict['overallStatus'] != None):
          logger.debug('CIMC (%s) update status: %s' %(self.cimcIpAddress, str(responseDict['overallStatus'])))
        del responseDict
        return

    if (responseDict['updateEndTime'] == None):
      logger.debug('CIMC (%s), did not receive proper status response.' %(self.cimcIpAddress))

    if (responseDict['updateEndTime'] != None):
      if (responseDict['updateEndTime'] != 'NA'):
        logger.info('CIMC (%s) update completed at [%s].' %(self.cimcIpAddress, str(responseDict['updateEndTime'])))
        self.lastTaskRetriable = False

    if (responseDict['overallStatus'] != None):
#      f.write(responseDict['overallStatus'])
 #     print '*** Overall Status written to file : (%s)  for CIMC (%s)' %(responseDict['overallStatus'], self.cimcIpAddress)
      strPos = str(responseDict['overallStatus']).lower().find("error");	
      if (strPos != -1 ):
        logger.error('Firmware Update did not start for CIMC (%s) As there is an ERROR in status. Rsp: %s' %(self.cimcIpAddress, responseData))
        self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_RESPONSE
        self.lastTaskRetriable = False
        self.updateFailureCause = ('Firmware update did not start. Error: %s' %(str(responseDict['overallStatus'])))
	return

      logger.debug('CIMC (%s) update status: %s' %(self.cimcIpAddress, str(responseDict['overallStatus'])))
    
    if (self.updateCompleted == True):
      logger.critical('CIMC (%s) update completed.' %(self.cimcIpAddress))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_SUCCESSFULL
      self.lastTaskRetriable = False
    else:
      logger.debug('CIMC (%s) update is continuing.' %(self.cimcIpAddress))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_RCVD_STATUS_RESPONSE
      self.lastTaskRetriable = True
    del responseDict



  # Request to see if any update is going on this server
  def HuuUpdateGetUpdaterStatus(self, logger):
    responseData = self.ConfigResolveClass(logger, 'huuFirmwareUpdater')

    if (responseData == None):
      logger.error('Did not get response for updater request from CIMC (' + self.cimcIpAddress + ')')
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATER_RESPONSE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      self.updateCompleted = False
      return

    # Process the XML response
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'configResolveClass', 'response', 'errorCode', 'errorDescr')
    if (responseDict == None):
      logger.error('Unable to process CIMC (%s) updater response: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATER_RESPONSE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      self.updateCompleted = False
      return

    if (responseDict['response'] != "yes"):
      logger.error('Updater response is not valid from CIMC (%s). Rsp: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATER_RESPONSE
      del responseDict
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      self.updateCompleted = False
      return

    if (responseDict['errorCode'] != None):
      if (responseDict['errorDescr'] != None):
        if ("Authorization required" in str(responseDict['errorDescr'])):
          self.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT
          logger.error('Login timed out for CIMC (%s). Rsp: %s' %(self.cimcIpAddress, responseData))
          self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATER_RESPONSE
          del responseDict
          self.lastTaskRetriable = True
          self.updateFailureCause = 'CIMC unresponsive'
          self.updateCompleted = False
          return
      else:
        logger.debug('Ignore error for CIMC (%s). Rsp: %s' %(self.cimcIpAddress, responseData))

    del responseDict
    self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_RCVD_UPDATER_RESPONSE

    # Process the remaining XML data
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'huuFirmwareUpdater',
		'updateComponent', 'adminState', 'stopOnError')

    if (responseDict['updateComponent'] == None or responseDict['stopOnError'] == None):
      logger.error('No firmware update running for CIMC (%s).' %(self.cimcIpAddress))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_RCVD_UPDATER_RESPONSE
      del responseDict
      self.lastTaskRetriable = True
      self.updateCompleted = True
      return

    if (responseDict['adminState'] != 'triggered'):
      logger.error('Updater response is not valid from CIMC (%s). Rsp: %s' %(self.cimcIpAddress, responseData))
      self.lastTaskRetriable = True
      self.updateCompleted = False

    del responseDict



  # Request to get the update details for successful update
  def HuuUpdateGetUpdateDetails(self, logger):
    responseData = self.ConfigResolveClass(logger, 'huuUpdateComponentStatus')

    if (responseData == None):
      logger.error('Did not get response for update details request from CIMC (' + self.cimcIpAddress + ')')
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_DETAILS_RESPONSE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      return

    # Process the XML response
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'configResolveClass', 'response')
    if (responseDict == None):
      logger.error('Unable to process CIMC (%s) get details response: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_DETAILS_RESPONSE
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      return

    if (responseDict['response'] != "yes"):
      logger.error('Get details response is not valid from CIMC (%s). Rsp: %s' %(self.cimcIpAddress, responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_DETAILS_RESPONSE
      del responseDict
      self.lastTaskRetriable = True
      self.updateFailureCause = 'CIMC unresponsive'
      return

    del responseDict

    # Process the remaining XML data
    responseDict = HuuXmlGetAttributeValue(logger, responseData, 'huuUpdateComponentStatus',
		'component', 'description')

    if (responseDict['component'] == None or responseDict['description'] == None):
      logger.error('Unable to get component update details for CIMC (%s).' %(self.cimcIpAddress))
      logger.debug('Updater response: %s' %(responseData))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_DETAILS_RESPONSE
      del responseDict
      self.lastTaskRetriable = True
      return

    del responseDict

    # Now get the details of each component updated and display it
    try:
      xmlDoc = parseString(responseData)
    except:
      logger.error('Failed to parse component update details for CIMC (%s).' %(self.cimcIpAddress))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_DETAILS_RESPONSE
      return

    if (xmlDoc == None):
      logger.error('Failed to parse component update details for CIMC (%s).' %(self.cimcIpAddress))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_DETAILS_RESPONSE
      return

    compList = xmlDoc.getElementsByTagName('huuUpdateComponentStatus')
    if (compList == None):
      logger.error('No component got updated for CIMC (%s).' %(self.cimcIpAddress))
      self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_RCVD_UPDATE_DETAILS_RESPONSE
      return

    for comp in compList:
      if (comp.hasAttribute('component')):
        compName = comp.getAttribute('component')  
      if (comp.hasAttribute('description')):
        compDesc = comp.getAttribute('description')  
      if (comp.hasAttribute('slot')):
        compSlot = comp.getAttribute('slot')  
      if (comp.hasAttribute('runningVersion')):
        compRVersion = comp.getAttribute('runningVersion')  
      if (comp.hasAttribute('newVersion')):
        compNVersion = comp.getAttribute('newVersion')  
      if (comp.hasAttribute('updateStatus')):
        compUStatus = comp.getAttribute('updateStatus')  
      if (comp.hasAttribute('errorDescription')):
        compEDesc = comp.getAttribute('errorDescription')

      if (compUStatus != 'Completed'):
        if (compName.upper() == 'BIOS' and compUStatus == 'InProgress'):
          pass
        else:
          print '*** Firmware update for a component (%s) failed for CIMC (%s). Error = %s' %(compDesc, self.cimcIpAddress, compEDesc)

      logger.info('CIMC (%s) - Component: %s, Description: %s, Slot: %s runningVersion: %s, newVersion: %s, updateStatus: %s, errorDescription: %s' %(self.cimcIpAddress, compName, compDesc, compSlot, compRVersion, compNVersion, compUStatus, compEDesc))

    self.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_RCVD_UPDATE_DETAILS_RESPONSE



  def ConfigResolveClass(self, logger, classId):
    configRsvRequest ="""<configResolveClass cookie="cookieValue" inHierarchical="false" classId="classIdValue"/>"""

    configRsvRequest = configRsvRequest.replace('cookieValue', self.cookie)
    configRsvRequest = configRsvRequest.replace('classIdValue', classId)

    logger.debug('ConfigResolve request data==>' + configRsvRequest)

    uri = self.Uri() + '/nuova'

    logger.debug('configRsvRequest uri data==>' + uri)

    # Send the XML request over http/https
    req = Request(url=uri, data=configRsvRequest)
    try:
      urlId = urlopen(req, timeout = 120)
    except HTTPError, e:
      logger.error('The CIMC (%s) couldn\'t fulfill the request. Error code: %s' %(self.cimcIpAddress, e.code))
      return None
    except URLError, e:
      logger.error('We failed to reach CIMC (%s). Reason: %s ' %(self.cimcIpAddress, e.reason))
      return None
    except BadStatusLine:
      logger.error('CIMC (%s) returning empty page. Check the XML support status of CIMC.' %(self.cimcIpAddress))
      return None
    except:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
      return None
    else:
      rsp = urlId.read()
      if (rsp == None):
        logger.debug('ConfigResolve response empty from CIMC (' + self.cimcIpAddress + ')')
        return None
    
      logger.debug('CIMC (' + self.cimcIpAddress + ') ConfigResolve response==>' + rsp)

      return rsp
    return None


  def CheckAndSetCDROMBootOrder(self, logger):
   
    getBootOrderRequest = """<configConfMo cookie="cookieValue" dn="sys/rack-unit-1/boot-policy" inHierarchical="true"> <inConfig> <lsbootDef dn="sys/rack-unit-1/boot-policy" rebootOnUpdate="no" status="modified"><lsbootVirtualMedia access="read-only" order="1" status="created" rn="vm-read-writei"/></lsbootDef> </inConfig> </configConfMo>"""

    getBootOrderRequest = getBootOrderRequest.replace('cookieValue', self.cookie)

    logger.debug('getBootOrderRequest request data==>' + getBootOrderRequest)
    
    uri = self.Uri() + '/nuova'
    
    logger.debug('getBootOrderRequest uri data==>' + uri)
    
    # Send the XML request over http/https
    
    req = Request(url=uri, data=getBootOrderRequest)
    try:
      urlId = urlopen(req, timeout = 180)
    except HTTPError, e:
      logger.error('The CIMC (%s) couldn\'t fulfill the request. Error code: %s' %(self.cimcIpAddress, e.code))
      return None
    except URLError, e:
      logger.error('We failed to reach CIMC (%s). Reason: %s ' %(self.cimcIpAddress, e.reason))
      return None
    except BadStatusLine:
      logger.error('CIMC (%s) returning empty page. Check the XML support status of CIMC.' %(self.cimcIpAddress))
      return None
    except:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
      return None
    else:
      rsp = urlId.read()
      if (rsp == None):
        logger.error('configMoRequest response empty from CIMC (' + self.cimcIpAddress + ')')
        return None
    
      logger.debug('CIMC (' + self.cimcIpAddress + ') configMoRequest response==>' + rsp)

    responseDict =HuuXmlGetAttributeValue(logger, rsp, 'configConfMo', 'response','errorCode', 'errorDescr')
      
    if (responseDict == None):
      logger.debug('Unable to process the SetBootOrder response (' + rsp + ') data')
      return None

    if (responseDict['response'] == None):
      logger.error('SetBootOrder response is not valid from CIMC (%s)' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['response'] != "yes"):
      logger.error('SetBootOrder response is not valid from CIMC (%s). Response is None' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['errorCode'] != None):
      logger.error('SetBootOrder error code: %s from CIMC (%s). Setting boot order change flag as false' %(str(responseDict['errorCode']), self.cimcIpAddress))
      if (responseDict['errorDescr'] != None):
        logger.error('SetBootOrder reason for CIMC (%s),  errorDescr: %s.' %(self.cimcIpAddress,str(responseDict['errorDescr'])))
        self.updateFailureCause = responseDict['errorDescr']

      del responseDict
      self.cdromAdded = False      
      return None
    
    logger.debug('Setting boot order change flag as True')  
    self.cdromAdded = True  
    return None


  def CheckAndSetUEFIsecureboot(self, logger):
    usbRequest = """<configResolveClass cookie='cookieValue' inHierarchical='false' classId='lsbootBootSecurity'/>"""

    usbRequest = usbRequest.replace('cookieValue', self.cookie)

    logger.debug('UEFI secure boot request data==>' + usbRequest)

    uri = self.Uri() + '/nuova'

    logger.debug('usbRequest uri data==>' + uri)
 
    # Send the XML request over http/https
    
    req = Request(url=uri, data=usbRequest)
    try:
      urlId = urlopen(req, timeout = 180)
    except HTTPError, e:
      logger.error('The CIMC (%s) couldn\'t fulfill the request. Error code: %s' %(self.cimcIpAddress, e.code))
      return None
    except URLError, e:
      logger.error('We failed to reach CIMC (%s). Reason: %s ' %(self.cimcIpAddress, e.reason))
      return None
    except BadStatusLine:
      logger.error('CIMC (%s) returning empty page. Check the XML support status of CIMC.' %(self.cimcIpAddress))
      return None
    except:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
      return None
    else:
      rsp = urlId.read()
      if (rsp == None):
        logger.error('configMoRequest response empty from CIMC (' + self.cimcIpAddress + ')')
        return None
    
      logger.debug('CIMC (' + self.cimcIpAddress + ') configMoRequest response==>' + rsp)

    responseDict =HuuXmlGetAttributeValue(logger, rsp, 'configResolveClass', 'response','errorCode', 'errorDescr')
      
    if (responseDict == None):
      logger.debug('Unable to process the UEFIsecureboot response (' + rsp + ') data')
      return None

    if (responseDict['response'] == None):
      logger.error('Get UEFIsecureboot response is not valid from CIMC (%s)' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['response'] != "yes"):
      logger.error('Get UEFIsecureboot response is not valid from CIMC (%s). Response is None' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['errorCode'] != None):
      logger.error('Get UEFIsecureboot error code: %s from CIMC (%s). ' %(str(responseDict['errorCode']), self.cimcIpAddress))
      if (str(responseDict['errorDescr']) == "XML PARSING ERROR"):
        logger.debug('UEFI secure boot feature is not applicable for (%s) . ' %(self.cimcIpAddress))
	self.uefifeature = False
	return None
      if (responseDict['errorDescr'] != None):
        logger.error('Get UEFIsecureboot failure reason for CIMC (%s),  errorDescr: %s.' %(self.cimcIpAddress,str(responseDict['errorDescr'])))
        self.updateFailureCause = responseDict['errorDescr']

      del responseDict
      return None
    
    if (self.uefifeature == False):
      logger.debug('uefifeature == False. UEFI secure boot feature is not applicable for (%s)' %(self.cimcIpAddress)) 
      return None

    logger.debug('Catalog Response UEFI boot rsp [ %s ] ' %(rsp) )  
    responseDict =HuuXmlGetAttributeValue(logger, rsp, 'lsbootBootSecurity', 'secureBoot')

    if (responseDict == None):
      logger.debug('Unable to process the UEFIsecureboot response (' + rsp + ') data')
      del responsedict	
      return None

    if (responseDict['secureBoot'] == None):
      logger.error('Get UEFIsecureboot response is not valid from CIMC (%s)' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['secureBoot'] == "enabled"):
      logger.debug('Get UEFIsecureboot response is ENABLED. Setting it to disable. %s' %(self.cimcIpAddress))
      self.uefiboot = True
      self.DisableUEFIsecureboot(logger)
      del responseDict
    logger.debug('feature flag === (%s) ' %(self.uefifeature))
    return None

  def ConfigConfMo(self, logger):

    #before firing Update request, check if CD ROM is present in the boot order. If CD ROM is not present then add it.
    #Also make cdromAdded = True. At the time of logout, if this flag is true then we need to remove the CD ROM from list
    #before firing Update request, check if UEFI secure-boot is enabled. If it is enabled, then disable it for the update.
    #Also make self.uefiboot = True. At the time of logout, if this flag is true then we need to enable the UEFIsecure boot again.

    #self.CheckAndSetCDROMBootOrder(logger)	
    self.CheckAndSetUEFIsecureboot(logger)	
    
    logger.debug(' FLag for cimc secure boot in COnfMO== (%s)' %(self.flagCimc))
    logger.debug(' CIMC SECURE BOOT VALUE == (%s)' %(self.cimcSecureBoot))

    if (self.flagCimc == True):
      configMoRequest ="""<configConfMo cookie='cookieValue' dn='sys/huu/firmwareUpdater'> <inConfig> <huuFirmwareUpdater dn='sys/huu/firmwareUpdater'  adminState='trigger' remoteIp='remoteIpValue' remoteShare=remoteImageLoc mapType='shareTypeValue' username=userNameValue password=pwdValue stopOnError='stopOnErrorValue' timeOut='timeOutValue' verifyUpdate='verifyUpdateValue' updateComponent='updateComponentValue' cimcSecureBoot='cimcSecureValue'/></inConfig></configConfMo>"""
    else:
      configMoRequest ="""<configConfMo cookie='cookieValue' dn='sys/huu/firmwareUpdater'> <inConfig> <huuFirmwareUpdater dn='sys/huu/firmwareUpdater'  adminState='trigger' remoteIp='remoteIpValue' remoteShare=remoteImageLoc mapType='shareTypeValue' username=userNameValue password=pwdValue stopOnError='stopOnErrorValue' timeOut='timeOutValue' verifyUpdate='verifyUpdateValue' updateComponent='updateComponentValue'/></inConfig></configConfMo>"""

    configMoRequest = configMoRequest.replace('cookieValue', self.cookie)    
    configMoRequest = configMoRequest.replace('remoteIpValue', self.remoteShareIp)    
    configMoRequest = configMoRequest.replace('shareTypeValue', self.shareType)    
    configMoRequest = configMoRequest.replace('userNameValue', quoteattr(self.remoteShareUser))    
    configMoRequest = configMoRequest.replace('pwdValue', quoteattr(self.remoteSharePassword))    
    configMoRequest = configMoRequest.replace('stopOnErrorValue', self.updateStopOnError)    
    configMoRequest = configMoRequest.replace('timeOutValue', self.updateTimeout)    
    configMoRequest = configMoRequest.replace('verifyUpdateValue', self.updateVerify)    
    configMoRequest = configMoRequest.replace('updateComponentValue', self.updateComponent)    

    if (self.flagCimc == True):
      configMoRequest = configMoRequest.replace('cimcSecureValue', self.cimcSecureBoot)    
    
    if (self.shareDirectory[-1] == '/'):
      remoteImage = self.shareDirectory + self.updateImageFile
    else:
      remoteImage = self.shareDirectory + '/' + self.updateImageFile
    configMoRequest = configMoRequest.replace('remoteImageLoc', quoteattr(remoteImage))    

    logger.debug('configMoRequest request data==>' + configMoRequest)

    uri = self.Uri() + '/nuova'

    #logger.debug('configMoRequest uri data==>' + uri)

    # Send the XML request over http/https
    req = Request(url=uri, data=configMoRequest)
    try:
      urlId = urlopen(req, timeout = 180)
    except HTTPError, e:
      logger.error('The CIMC (%s) couldn\'t fulfill the request. Error code: %s' %(self.cimcIpAddress, e.code))
      return None
    except URLError, e:
      logger.error('We failed to reach CIMC (%s). Reason: %s ' %(self.cimcIpAddress, e.reason))
      return None
    except BadStatusLine:
      logger.error('CIMC (%s) returning empty page. Check the XML support status of CIMC.' %(self.cimcIpAddress))
      return None
    except:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
      return None
    else:
      rsp = urlId.read()
      if (rsp == None):
        logger.error('configMoRequest response empty from CIMC (' + self.cimcIpAddress + ')')
        return None
    
      logger.debug('CIMC (' + self.cimcIpAddress + ') configMoRequest response==>' + rsp)

      return rsp
    return None


  def RemoveCDROMBootOrder (self, logger):

    if ( self.cdromAdded == False ):
      logger.debug('No Need to reset the boot order ')
      return None

    getBootOrderRequest = """<configConfMo cookie='cookieValue' dn='sys/rack-unit-1/boot-policy' inHierarchical='true'> <inConfig> <lsbootDef dn='sys/rack-unit-1/boot-policy' rebootOnUpdate='no' status='modified'><lsbootVirtualMedia access='read-only' order='1' status='deleted' rn='vm-read-write'/></lsbootDef> </inConfig> </configConfMo>"""

    getBootOrderRequest = getBootOrderRequest.replace('cookieValue', self.cookie)

    logger.debug('getBootOrderRequest request data==>' + getBootOrderRequest)
    
    uri = self.Uri() + '/nuova'
    
    logger.debug('getBootOrderRequest uri data==>' + uri)
    
    # Send the XML request over http/https
    
    req = Request(url=uri, data=getBootOrderRequest)
    try:
      urlId = urlopen(req, timeout = 180)
    except HTTPError, e:
      logger.error('The CIMC (%s) couldn\'t fulfill the request. Error code: %s' %(self.cimcIpAddress, e.code))
      return None
    except URLError, e:
      logger.error('We failed to reach CIMC (%s). Reason: %s ' %(self.cimcIpAddress, e.reason))
      return None
    except BadStatusLine:
      logger.error('CIMC (%s) returning empty page. Check the XML support status of CIMC.' %(self.cimcIpAddress))
      return None
    except:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
      return None
    else:
      rsp = urlId.read()
      if (rsp == None):
        logger.error('configMoRequest response empty from CIMC (' + self.cimcIpAddress + ')')
        return None
    
      logger.debug('CIMC (' + self.cimcIpAddress + ') configMoRequest response==>' + rsp)

    responseDict =HuuXmlGetAttributeValue(logger, rsp, 'configConfMo', 'response','errorCode', 'errorDescr')
      
    if (responseDict == None):
      logger.debug('Unable to process the SetBootOrder response (' + rsp + ') data')
      return None

    if (responseDict['response'] == None):
      logger.error('SetBootOrder response is not valid from CIMC (%s)' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['response'] != "yes"):
      logger.error('SetBootOrder response is not valid from CIMC (%s). Response is None' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['errorCode'] != None):
      logger.error('SetBootOrder error code: %s from CIMC (%s). Setting boot order change flag as false' %(str(responseDict['errorCode']), self.cimcIpAddress))
      if (responseDict['errorDescr'] != None):
        logger.error('SetBootOrder reason for CIMC (%s),  errorDescr: %s.' %(self.cimcIpAddress,str(responseDict['errorDescr'])))
        self.updateFailureCause = responseDict['errorDescr']

      del responseDict
      self.cdromAdded = False      
      return None
    
    logger.debug('Resetting Setting boot order change flag as False')  
    self.cdromAdded = False  
    return None
    
  def DisableUEFIsecureboot (self, logger):
    getUEFIsecurebootRequest = """<configConfMo cookie='cookieValue' inHierarchical='false'> <inConfig><lsbootBootSecurity dn='sys/rack-unit-1/boot-policy/boot-security' secureBoot='disable'></lsbootBootSecurity></inConfig></configConfMo>"""

    getUEFIsecurebootRequest = getUEFIsecurebootRequest.replace('cookieValue', self.cookie)

    logger.debug('getUEFIsecureboot request data==>' + getUEFIsecurebootRequest)
    
    uri = self.Uri() + '/nuova'
    
    logger.debug('getUEFIsecureboot uri data==>' + uri)
    
    # Send the XML request over http/https
    
    req = Request(url=uri, data=getUEFIsecurebootRequest)
    try:
      urlId = urlopen(req, timeout = 180)
    except HTTPError, e:
      logger.error('The CIMC (%s) couldn\'t fulfill the request. Error code: %s' %(self.cimcIpAddress, e.code))
      return None
    except URLError, e:
      logger.error('We failed to reach CIMC (%s). Reason: %s ' %(self.cimcIpAddress, e.reason))
      return None
    except BadStatusLine:
      logger.error('CIMC (%s) returning empty page. Check the XML support status of CIMC.' %(self.cimcIpAddress))
      return None
    except:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
      return None
    else:
      rsp = urlId.read()
      if (rsp == None):
        logger.error('configMoRequest response empty from CIMC (' + self.cimcIpAddress + ')')
        return None
    
      logger.debug('CIMC (' + self.cimcIpAddress + ') configMoRequest response==>' + rsp)

    responseDict =HuuXmlGetAttributeValue(logger, rsp, 'configConfMo', 'response','errorCode', 'errorDescr')
      
    if (responseDict == None):
      logger.debug('Unable to process the SetUEFIboot response (' + rsp + ') data')
      return None

    if (responseDict['response'] == None):
      logger.error('SetUEFIboot response is not valid from CIMC (%s)' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['response'] != "yes"):
      logger.error('SetUEFIboot response is not valid from CIMC (%s). Response is None' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['errorCode'] != None):
      logger.error('SetUEFIboot error code: %s from CIMC (%s). Setting boot order change flag as true' %(str(responseDict['errorCode']), self.cimcIpAddress))
      if (responseDict['errorDescr'] != None):
        logger.error('SetUEFIboot reason for CIMC (%s),  errorDescr: %s.' %(self.cimcIpAddress,str(responseDict['errorDescr'])))
        self.updateFailureCause = responseDict['errorDescr']

      del responseDict
      return None
    
    logger.debug('State of UEFI secure boot changed to disable, flag set to true')  
    return None
    
  def EnableUEFIsecureboot (self, logger):

    if ( self.uefiboot == False ):
      logger.debug('No Need to reset the UEFI secure boot ')
      return None

    logger.debug('Enable ing secure boot')
    getUEFIsecurebootRequest = """<configConfMo cookie='cookieValue' inHierarchical='false'> <inConfig><lsbootBootSecurity dn='sys/rack-unit-1/boot-policy/boot-security' secureBoot='enable'></lsbootBootSecurity></inConfig></configConfMo>"""

    getUEFIsecurebootRequest = getUEFIsecurebootRequest.replace('cookieValue', self.cookie)

    logger.debug('getUEFIsecureboot request data==>' + getUEFIsecurebootRequest)
    
    uri = self.Uri() + '/nuova'
    
    logger.debug('getUEFIsecureboot uri data==>' + uri)
    
    # Send the XML request over http/https
    
    req = Request(url=uri, data=getUEFIsecurebootRequest)
    try:
      urlId = urlopen(req, timeout = 180)
    except HTTPError, e:
      logger.error('The CIMC (%s) couldn\'t fulfill the request. Error code: %s' %(self.cimcIpAddress, e.code))
      return None
    except URLError, e:
      logger.error('We failed to reach CIMC (%s). Reason: %s ' %(self.cimcIpAddress, e.reason))
      return None
    except BadStatusLine:
      logger.error('CIMC (%s) returning empty page. Check the XML support status of CIMC.' %(self.cimcIpAddress))
      return None
    except:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
      return None
    else:
      rsp = urlId.read()
      if (rsp == None):
        logger.error('configMoRequest response empty from CIMC (' + self.cimcIpAddress + ')')
        return None
    
      logger.debug('CIMC (' + self.cimcIpAddress + ') configMoRequest response==>' + rsp)

    responseDict =HuuXmlGetAttributeValue(logger, rsp, 'configConfMo', 'response','errorCode', 'errorDescr')
      
    if (responseDict == None):
      logger.debug('Unable to process the SetUEFIboot response (' + rsp + ') data')
      return None

    if (responseDict['response'] == None):
      logger.error('SetUEFIboot response is not valid from CIMC (%s)' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['response'] != "yes"):
      logger.error('SetUEFIboot response is not valid from CIMC (%s). Response is None' %(self.cimcIpAddress))
      del responseDict
      return None

    if (responseDict['errorCode'] != None):
      logger.error('SetUEFIboot error code: %s from CIMC (%s). Setting boot order change flag as false' %(str(responseDict['errorCode']), self.cimcIpAddress))
      if (responseDict['errorDescr'] != None):
        logger.error('SetUEFIboot reason for CIMC (%s),  errorDescr: %s.' %(self.cimcIpAddress,str(responseDict['errorDescr'])))
        self.updateFailureCause = responseDict['errorDescr']

      del responseDict
      return None
    
    logger.debug('Resetting Setting boot order change flag as False')  
    return None
     


  def AaaLogin(self, logger):
    loginRequest = """<aaaLogin inName=admin inPassword=password></aaaLogin>"""

    loginRequest = loginRequest.replace('admin', quoteattr(self.username))
    loginRequest = loginRequest.replace('password', quoteattr(self.password))

    logger.debug('Login request data==>' + loginRequest)

    uri = self.Uri() + '/nuova'

    #logger.debug('Login uri data==>' + uri)

    # Send the XML request over http/https
    req = Request(url=uri, data=loginRequest)
    try:
      urlId = urlopen(req, timeout = 120)
    except HTTPError, e:
      logger.error('The CIMC (%s) couldn\'t fulfill the request. Error code: %s' %(self.cimcIpAddress, e.code))
      return None
    except URLError, e:
      logger.error('We failed to reach CIMC (%s). Reason: %s ' %(self.cimcIpAddress, e.reason))
      # Try toggling the ssl support
      # if (self.noSsl == True):
      #  self.noSsl = False
      #else:
      #  self.noSsl = True
      return None
    except BadStatusLine:
      logger.error('CIMC (%s) returning empty page. Check the XML support status of CIMC.' %(self.cimcIpAddress))
      return None
    except:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
      return None
    else:
      rsp = urlId.read()
      if (rsp == None):
        logger.debug('Login response empty')
        return None
   
      logger.debug('Login Successful') 
#      logger.debug('Login response==>' + rsp)

      return rsp
    return None


  def AaaKeepAlive(self, logger):
    keepAliveReq = """<aaaKeepAlive cookie="cookieValue"> </aaaKeepAlive>"""

    keepAliveReq = keepAliveReq.replace('cookieValue', self.cookie)
    logger.info('KeepAlive request data==>' + loginRequest)

    uri = self.Uri() + '/nuova'
    # Send the XML request over http/https
    req = Request(url=uri, data=keepAliveReq)
    try:
      urlId = urlopen(req, timeout = 120)
    except HTTPError, e:
      logger.error('The CIMC (%s) couldn\'t fulfill the request. Error code: %s' %(self.cimcIpAddress, e.code))
      return None
    except URLError, e:
      logger.error('We failed to reach CIMC (%s). Reason: %s ' %(self.cimcIpAddress, e.reason))
      return None
    except BadStatusLine:
      logger.error('CIMC (%s) returning empty page. Check the XML support status of CIMC.' %(self.cimcIpAddress))
      return None
    except:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
      return None
    else:
      rsp = urlId.read()
      if (rsp == None):
        logger.info('KeepAlive response empty')
        return None
    
      logger.info('KeepAlive response==>' + rsp)

    return rsp


  def AaaLogout(self, logger):

    #self.RemoveCDROMBootOrder (logger)
    if (self.uefifeature == True):         
      logger.info('self.uefifeature is true. Enabling the feature in logout')
      self.EnableUEFIsecureboot (logger)
    else:
      logger.info('UEFI feature is disabled in this box. No need to call enable')

    logoutReq = """<aaaLogout cookie="cookieValue" inCookie="inCookieValue"> </aaaLogout>"""

    logoutReq = logoutReq.replace('cookieValue', self.cookie)
    logoutReq = logoutReq.replace('inCookieValue', self.cookie)
    logger.info('Logout request data==>' + logoutReq)

    uri = self.Uri() + '/nuova'
    # Send the XML request over http/https
    req = Request(url=uri, data=logoutReq)
    try:
      urlId = urlopen(req, timeout = 120)
    except HTTPError, e:
      logger.error('The CIMC (%s) couldn\'t fulfill the request. Error code: %s' %(self.cimcIpAddress, e.code))
      return None
    except URLError, e:
      logger.error('We failed to reach CIMC (%s). Reason: %s ' %(self.cimcIpAddress, e.reason))
      return None
    except BadStatusLine:
      logger.error('CIMC (%s) returning empty page. Check the XML support status of CIMC.' %(self.cimcIpAddress))
      return None
    except:
      logger.error('Could not get response from CIMC (%s).' %(self.cimcIpAddress))
      return None
    else:
      rsp = urlId.read()
      if (rsp == None):
        logger.error('Logout response empty')
        return None
    
      logger.info('Logout response==>' + rsp)

    return rsp


class HuuUpdate:
  def __init__(self):
    self.configFile = None
    self.configFileId = -1
    self.logFile = None
    self.logFileId = -1
    self.logLevel = None
    self.pendingOperationQueue = None
    self.receivedResponseQueue = None
    self.successfullUpdateList = []
    self.failedUpdateList = []
    self.ipAddress = None
    self.userName = None
    self.password = None
    self.imageFile = None
    self.remoteShareIp = None
    self.shareType = None
    self.shareDirectory = None
    self.remoteShareUser = None
    self.remoteSharePassword = None
    self.componentlist = None 
    self.useSecure = "yes"
    self.rebootCimc = "no"
    self.cimcSecureBoot = None
    self.inFile = None
    self.generateKey = False
    self.dispComponentList = False
    self.flagCimc = False
    self.updateTimeout='60'
    self.updateStopOnError="no"
    self.updateVerify="no"
  def generateKeys(self, logger):
	if (supportCrypto == False):
		print '[Error] Cannot use encrypted passwords. Needed package unavailable. Need pycrypto >= 2.6'
		sys.exit(0);
	logger.debug('Start key generation !!')
	try:
		pubKeyFile = open('keys.pub','w')
	except IOError:
		logger.error('Unable to create public key')
		print ('Error: Key generation failed')
	
	try:
		prvKeyFile = open('keys.pem','w')
	except IOError:
		logger.error('Unable to create private key')
		print ('Error: Key generation failed')
	
	random_keygen = Random.new().read
	try:	
		key = RSA.generate(1024, random_keygen)
	except ValueError, e:
		logger.error('Unable to generate key object')
		print ('Error: Key generation failed')
		return None
	try:
		pubKey = key.publickey()	
	except ValueError, e:
		logger.error('Unable to generate public key object')
		print ('Error: Key generation failed')
		return None
	
	#write public key to the file
	passPhrase = getpass.getpass ('Enter pass phrase for the key (Enter to continue) ?')
	
	pubKeyFile.write(pubKey.exportKey('PEM',passPhrase))
	prvKeyFile.write(key.exportKey('PEM',passPhrase))
		
	print ('Key Generation done !!')
	print ('Private key file --> keys.pem')
	print ('Public key file --> keys.pub')

  def encryptFile (self, logger):
	if (supportCrypto == False):
		print '[Error] Cannot use encrypted passwords. Needed package unavailable. Need pycrypto >= 2.6'
		sys.exit(0);
	passPhrase = getpass.getpass ('Enter pass phrase for the key (Enter to continue) ?')
	raw_password = getpass.getpass ('Enter password to encrypt ?')
	if (raw_password == None):
		logger.error('Password cannot be blank')
		print ('Error: Password cannot be blank')
		return None
	#Import the public key
	try:
		pubKeyFile = open (self.inFile,'rb')	
	except IOError:
		logger.error('Unable to open the public key file')
		print ('Error: Unable to open the public key file')
		return None
	try:
		pubKey =  RSA.importKey(pubKeyFile.read(), passPhrase)	
	except ValueError, e:
		logger.error('Unable to generate public key object.')
		print ('Error: Unable to open the public key file.')
		return None
	enc_password = pubKey.encrypt(raw_password,1024)
	
	try:
		f = open ('password.key','w')
	except IOError:
		logger.error('Unable to write encrypted password')
		print ('Error: Unable to generate encrypted password')
		return None
	f.write(enc_password[0])
	
	print ('Encrypted password generated. --> password.key')		
	
  def decryptText (self, filePath, logger):
	
	if (supportCrypto == False):
		print '[Error] Cannot use encrypted passwords. Needed package unavailable. Need pycrypto >= 2.6'
		sys.exit(0);
		 
	raw_password = None	
	passPhrase = getpass.getpass ('Enter pass phrase for the key (Enter to continue) ?')
	#Import the public key
	try:
		prvKeyFile = open ('keys.pem','rb')	
	except IOError:
		logger.error('Unable to open the pem key file')
		print ('Error: Unable to open the pem key file')
		sys.exit(0)
	try:
		prvKey =  RSA.importKey(prvKeyFile.read(), passPhrase)	
	except ValueError, e:
		logger.error('Unable to generate pem key object.')
		print ('Error: Unable to open the pem key file.')
		sys.exit(0)
	try:
		f = open (filePath,'r')
	except IOError:
		logger.error('Unable to open password file')
		print ('Error: Unable to open password file')
		sys.exit(0)	
	
	raw_password = prvKey.decrypt(f.read())
	if (raw_password == None ):
		logger.error('Decryption failed !!')
		print ('Error: Decryption failed ')
		sys.exit(0)
	return raw_password
	
			

  def HuuUpdateProcessCommandLineArgs(self, logger):
    cmdLineparser = optparse.OptionParser(usage='%prog [options]', version='%prog 1.1')

    singleServerOpts = optparse.OptionGroup(cmdLineparser, 'Single server options',
		                             'This options to be used while upgrading a single server firmware',)

    singleServerOpts.add_option('-a', '--address', action='store', type='string', dest='ipaddress',
		                        help='CIMC IP address', metavar='a.b.c.d')
    singleServerOpts.add_option('-u', '--user', action='store', type='string', dest='username',
		                        help='Username of the CIMC admin user')
    singleServerOpts.add_option('-p', '--password', action='store', type='string', dest='password',
                                help='Password of the CIMC admin user')
    singleServerOpts.add_option('-m', '--imagefile', action='store', type='string', dest='imagefile',
                                help='HUU iso image file name', metavar='ucs-c240-huu-146.iso')
    singleServerOpts.add_option('-i', '--remoteshareip', action='store', type='string', dest='remoteshareip',
                                help='IP address of the remote share', metavar='a.b.c.d')
    singleServerOpts.add_option('-d', '--sharedirectory', action='store', type='string', dest='location',
                                help='Directory location of the image file in remote share', metavar='/data/image')
    singleServerOpts.add_option('-t', '--sharetype', action='store', type='string', dest='sharetype',
                                help='Type of remote share', metavar='cifs/nfs/www')
    singleServerOpts.add_option('-r', '--remoteshareuser', action='store', type='string', dest='remoteshareuser',
                                help='Remote share user name')
    singleServerOpts.add_option('-w', '--remotesharepassword', action='store', type='string', dest='remotesharepassword',
                                help='Remote share user password')
    singleServerOpts.add_option('-y', '--componentlist', action='store', type='string', dest='componentlist',
                                help='Component List')
    singleServerOpts.add_option('-f', '--logrecordfile', action='store', type='string', dest='logfile',
                                default="update_huu.log", help='Log file name where log data will be saved')
    singleServerOpts.add_option('-b', '--cimcsecureboot', action='store', type='string', dest='cimcSecureBoot',
				help='Use CimcSecureBoot. Default is NO. Options yes/no')
    singleServerOpts.add_option('-R', '--reboot', action='store', type='string', dest='rebootCimc',
                                default ="no", help='Reboot CIMC before starting update. Options yes/no')
    singleServerOpts.add_option('-T', '--timeoutalue', action='store', type='string', dest='updateTimeout',
				help='Timeout Value for update')
    singleServerOpts.add_option('-o', '--stopOnError', action='store', type='string', dest='updateStopOnError',
				help='Use this option if you want to stop the firmware update once an error is encountered?')
    singleServerOpts.add_option('-v', '--updateverify', action='store', type='string', dest='updateVerify',
				help='Use this option to verify update after reboot')

    singleServerOpts.add_option('-S', '--Secure', action='store', type='string', dest='useSecure',
                                default="yes", help='Use HTTPS. Default is yes. Options yes/no')

#    singleServerOpts.add_option('-n', '--loglevels', action='store', type='string', dest='loglevel',
#                                default='3', help='Log level - 0 (critical), 1 (error), 2 (warning), 3 (Info), 4 (Debug)')
    cmdLineparser.add_option_group(singleServerOpts)

    multipleServerOpts = optparse.OptionGroup(cmdLineparser, 'Multiple server update options',
                                     'This options to be used while upgrading multiple servers firmware',)
    multipleServerOpts.add_option('-c', '--configfile', action='store', type='string', dest='configfile',
                                help='Name of the file with the list of CIMC IP address and other data')
##    multipleServerOpts.add_option('-i', '--imagefile', action='store', type='string', dest='imagefile',
##                                help='HUU iso image name with full path')
    multipleServerOpts.add_option('-l', '--logfile', action='store', type='string', dest='logfile',
                                default="update_huu.log", help='Log file name where the log data will be saved')


    multipleServerOpts.add_option('-s', '--secure', action='store', type='string', dest='useSecure',
                                default="yes", help='Use HTTPS. Default is yes. Options yes/no')

# Options for Key generation and encryption
    multipleServerOpts.add_option('-e', '--encrypt', action='store', type='string', dest='inFile',
                                help='Public key file.')
    multipleServerOpts.add_option('-g', '--generatekey', action='store_true', dest='generateKey',
                                default = False, help='Generate public and private keys')
    multipleServerOpts.add_option('-j', '--displayComponentList', action='store_true', dest='dispComponentList',
                                default = False, help='Display List of component')

    multipleServerOpts.add_option('-V', '--Version', action='store_true', dest='version',
                                default = False, help='Display version.')

	
#    multipleServerOpts.add_option('-v', '--loglevel', action='store', type='string', dest='loglevel',
#                                default="3", help='Log level - 0 (critical), 1 (error), 2 (warning), 3 (Info), 4 (Debug)')
    cmdLineparser.add_option_group(multipleServerOpts)

    (options, args) = cmdLineparser.parse_args()

    if (options.version != None ):
	if (options.version == True ):
		print 'Version = %s' %(version)	
		sys.exit(0)

    if (options.configfile != None):
      self.configFile = options.configfile
    if (options.logfile != None):
      self.logFile = options.logfile
    if (options.ipaddress != None):
      self.ipAddress = options.ipaddress
    if (options.username != None):
      self.userName = options.username
    if (options.password != None):
      self.password = options.password
    if (options.imagefile != None):
      self.imageFile = options.imagefile
    if (options.remoteshareip != None):
      self.remoteShareIp = options.remoteshareip
    if (options.sharetype != None):
      self.shareType = options.sharetype
    if (options.location != None):
      self.shareDirectory = options.location
    if (options.remoteshareuser != None):
      self.remoteShareUser = options.remoteshareuser
    if (options.remotesharepassword != None):
      self.remoteSharePassword = options.remotesharepassword
    if (options.logfile != None):
      self.logFile = options.logfile
    if (options.componentlist != None):
      self.componentlist = options.componentlist
    if (options.useSecure != None ):
      self.useSecure = options.useSecure
    if (options.rebootCimc != None ):
      self.rebootCimc = options.rebootCimc
    if (options.cimcSecureBoot != None ):
      self.cimcSecureBoot = options.cimcSecureBoot
    if (options.updateTimeout != None ):
      self.updateTimeout = options.updateTimeout
    if (options.updateStopOnError != None ):
      self.updateStopOnError = options.updateStopOnError
    if (options.updateVerify != None ):
      self.updateVerify = options.updateVerify
    if (options.inFile != None ):
      self.inFile = options.inFile
    if (options.generateKey != None ):
      self.generateKey = options.generateKey
    if (options.dispComponentList != None ):
      self.dispComponentList = options.dispComponentList
#    self.logLevel = options.loglevel

    securityOptions = False

    if self.dispComponentList:
	if  options.username == None:
		print (' CIMC user name must be provided. Use --username ')
		sys.exit(0)
	if options.password == None:
		print (' CIMC password must be provided. Use --password ')
		sys.exit(0)
	if options.ipaddress == None:
		print (' CIMC IP address must be provided. Use --ipaddress ')
		sys.exit(0)
        if ( self.useSecure.lower() == "no" ):
          HuuUpdateHost.noSsl = True
        else:
          HuuUpdateHost.noSsl = False
	HuuUpdateHost.dispComponentList = True
	return


    if self.generateKey:
	if self.inFile:
		print (' Invalid option combination. Cannot use  --generateKey and --encrypt together ')
		sys.exit(0)
	elif options.configfile or self.ipAddress or self.userName or self.password or self.imageFile or self.remoteShareIp or self.shareType or\
self.shareDirectory or self.remoteShareUser or self.remoteSharePassword or self.componentlist:
		print ('Invalid option combination. Cannot use config file or update options with --generateKey ')
		sys.exit(0)
	else:
		securityOptions = True

	
    if self.inFile:
	if self.generateKey:
		print (' Invalid option combination. Cannot use  --generateKey and --encrypt together ')
		sys.exit(0)
	elif options.configfile or self.ipAddress or self.userName or self.password or self.imageFile or self.remoteShareIp or self.shareType or\
self.shareDirectory or self.remoteShareUser or self.remoteSharePassword or self.componentlist:
		print ('Invalid option combination. Cannot use config file or update options with --encrypt ')
		sys.exit(0)
	else:
		securityOptions = True

    correctOptions = True
    if self.ipAddress or self.userName or self.password or self.imageFile or self.remoteShareIp or self.shareType or\
self.shareDirectory or self.remoteShareUser or self.remoteSharePassword or self.componentlist:
      if options.configfile:
        print '[Error]: Can not mix single server option with multiple server option. Check help for more'
        sys.exit(0)
      if not self.ipAddress:
        print '[Error]: Mandatory option --address missing.'
        correctOptions = False
      if not self.userName:
        print '[Error]: Mandatory option --user missing.'
        correctOptions = False
      if not self.password:
        print '[Error]: Mandatory option --password missing.'
        correctOptions = False
      if not self.imageFile:
        print '[Error]: Mandatory option --imagefile missing.'
        correctOptions = False
      if not self.remoteShareIp:
        print '[Error]: Mandatory option --remoteshareip missing.'
        correctOptions = False
      if not self.shareDirectory:
        print '[Error]: Mandatory option --sharedirectory missing.'
        correctOptions = False
      if not self.shareType:
        print '[Error]: Mandatory option --sharetype missing.'
        correctOptions = False
      if not self.remoteShareUser:
        print '[Error]: Mandatory option --remoteshareuser missing.'
        correctOptions = False
      if not self.remoteSharePassword:
        print '[Error]: Mandatory option --remotesharepassword missing.'
        correctOptions = False
      if not self.componentlist:
	print '[Error]: Mandatory option --componentlist missing.'
	correctOptions = False
      if (correctOptions == False):
        sys.exit(0)
    elif options.configfile:
      print
      print 'Processing config file (%s) data' %(options.configfile)
      print
    elif securityOptions == True:
	print ' '	
    else:
      print '[Error]: Mandatory options missing. Try with -h for details. '
      sys.exit(0)

    # Update the class variables data for HuuUpdateHost class
    if (options.configfile == None): 
      HuuUpdateHost.remoteShareIp = self.remoteShareIp
      HuuUpdateHost.shareType = self.shareType
      HuuUpdateHost.shareDirectory = self.shareDirectory
      HuuUpdateHost.remoteShareUser = self.remoteShareUser
      HuuUpdateHost.remoteSharePassword = self.remoteSharePassword
      HuuUpdateHost.updateTimeout = self.updateTimeout
      HuuUpdateHost.updateStopOnError = self.updateStopOnError
      HuuUpdateHost.updateVerify = self.updateVerify
      HuuUpdateHost.updateComponent = self.componentlist
      HuuUpdateHost.rebootCimc = self.rebootCimc.lower();
      if ( self.useSecure.lower() == "no" ):
        HuuUpdateHost.noSsl = True
      else:
        HuuUpdateHost.noSsl = False
      if ( self.cimcSecureBoot != None and self.cimcSecureBoot.lower() == "yes" ):
	HuuUpdateHost.flagCimc = self.flagCimc
        HuuUpdateHost.cimcSecureBoot = 'yes'
      else:
        HuuUpdateHost.cimcSecureBoot = 'no'

  def HuuOpenConfigFile(self, logger):
    try:
      self.configFileId = open(self.configFile, 'r')
    except IOError:
      logger.error('Could not open file ' + self.configFile)
      logger.error("Config file open failed")
      return False
    return True


  def HuuUpdateProcessConfigFileData(self, logger):
    global cimcUpdateDict

    data = self.configFileId.readlines()
    if (data == None):
      logger.error('Config file is empty')
      return False

    updateTimeout = None
    updateStopOnError = None
    updateVerify = None
    updateComponent = None
    useHttps = None
    cimcSecureBoot = None
    commonPassword = False
    rebootCimc = 'no'

    for line in data:
      if (line[0] == '#'):
        continue
      if (line.isspace()):
        continue
      if "remoteshareip" in line:
        self.remoteShareIp = line.split('=')[1].strip()
        logger.info('remoteshareip: ' + self.remoteShareIp)
      elif "sharedirectory" in line:
        self.shareDirectory = line.split('=')[1].strip()
        if (self.shareDirectory == ''):
          self.shareDirectory ='/'
        logger.info('sharedirectory: ' + self.shareDirectory)
      elif "sharetype" in line:
        self.shareType = line.split('=')[1].strip()
        #self.shareType = self.shareType.upper()
        self.shareType = self.shareType
        logger.info('sharetype: ' + self.shareType)
      elif "remoteshareuser" in line:
        self.remoteShareUser = line.split('=')[1].strip()		
        logger.info('remoteshareuser: ' + self.remoteShareUser)
      elif "remotesharepassword" in line:
        self.remoteSharePassword = line.split('=')[1].strip()		
        logger.info('remotesharepassword: ' + self.remoteSharePassword)
      elif "remoteshare_passwordfile" in line:
	print ('Decryting Remote Share password ')
	filePath=line.split('=')[1].strip()
	raw_password = self.decryptText(filePath,logger)
	self.remoteSharePassword = raw_password
      elif "use_http_secure" in line:
        useHttps = line.split('=')[1].strip()		
        logger.info('useHttps: ' + useHttps)
      elif "use_cimc_secure" in line:
	self.flagCimc = True
        cimcSecureBoot = line.split('=')[1].strip()		
        logger.info('useCimcSecure: ' + cimcSecureBoot)
      elif "reboot_cimc" in line:
        rebootCimc = line.split('=')[1].strip()		
        logger.info('reboot_cimc: ' + rebootCimc)
      elif "update_timeout" in line:
        updateTimeout = line.split('=')[1].strip()		
        logger.info('update_timeout: ' + updateTimeout)
      elif "update_stop_on_error" in line:
        updateStopOnError = line.split('=')[1].strip()		
        logger.info('update_stop_on_error: ' + updateStopOnError)
      elif "update_verify" in line:
        updateVerify = line.split('=')[1].strip()		
        logger.info('update_verify: ' + updateVerify)
      elif "update_component" in line:
        updateComponent = line.split('=')[1].strip()		
        logger.info('update_component: ' + updateComponent)
      elif "cimc_password_file" in line:
	print ('Decrypting common CIMC password file ')
	filePath=line.split('=')[1].strip()
	raw_password = self.decryptText(filePath,logger)
	commonPassword = True
      elif "address=" in line and "user=" in line and "password=" in line:
        lineWords = line.split(',')
       
        for wrd in lineWords:
          if "address" in wrd:
            address = wrd.split('=')[1].strip()
          elif "user" in wrd:
            user = wrd.split('=')[1].strip()
          elif "password" in wrd:
            password = wrd.split('=')[1].strip()
          elif "image" in wrd:
            image = wrd.split('=')[1].strip()

#        logger.debug('Create entry for ' + address)
	if ( commonPassword == False ):
	        updateHost = HuuUpdateHost(address, user, password, image);
	else:
		updateHost = HuuUpdateHost(address, user, raw_password, image);
        cimcUpdateDict[address] = updateHost
      else:
        logger.error('Did not match anything.');
        logger.error('Ignoring line: ' + line)

    # Check if the config file contains no CIMC ip address to update
    if (len(cimcUpdateDict) <= 0):
      print 'Config file (%s) do not have any CIMC ip address to update firmware' %(self.configFile)
      return False

    # Update the class variables data for HuuUpdateHost class
    if (self.remoteShareIp != None):
      HuuUpdateHost.remoteShareIp = self.remoteShareIp
    else:
      logger.error('Remote share IP not provided, upgrade not possible')
      return False 
    if (self.shareType != None):
      HuuUpdateHost.shareType = self.shareType
    elif (self.sharetype != 'cifs' or self.sharetype != 'nfs'):
      logger.error('Unknow sharetype ' + self.sharetype + ' provided, upgrade not possible')
      return False 
    else:
      logger.error('Remote share type not provided, upgrade not possible')
      return False 
    if (self.shareDirectory != None):
      HuuUpdateHost.shareDirectory = self.shareDirectory
    else:
      logger.error('Remote share directory not provided, upgrade not possible')
      return False 
    if (self.remoteShareUser != None):
      HuuUpdateHost.remoteShareUser = self.remoteShareUser
    else:
      logger.error('Remote share user not provided, upgrade not possible')
      return False
    if (self.remoteSharePassword != None):
      HuuUpdateHost.remoteSharePassword = self.remoteSharePassword
    else:
      logger.error('Remote share password not provided, upgrade not possible')
      return False
    if (updateTimeout != None):
      HuuUpdateHost.updateTimeout = updateTimeout
    if (updateStopOnError != None):
      HuuUpdateHost.updateStopOnError = updateStopOnError
    else:
      HuuUpdateHost.updateStopOnError = 'no'
    if (updateVerify != None):
      HuuUpdateHost.updateVerify = updateVerify
    else:
      HuuUpdateHost.updateVerify = 'no'
    if (updateComponent != None):
      HuuUpdateHost.updateComponent = updateComponent
    else:
      HuuUpdateHost.updateComponent = 'all'
    if (useHttps != None):
      if (useHttps.lower() == 'no'):
        HuuUpdateHost.noSsl = True
      else:
        HuuUpdateHost.noSsl = False
    else:
      HuuUpdateHost.noSsl = False
    if (cimcSecureBoot != None):
      HuuUpdateHost.flagCimc = True
      if (cimcSecureBoot.lower() == 'yes'):
        HuuUpdateHost.cimcSecureBoot = 'yes'
      else:
        HuuUpdateHost.cimcSecureBoot = 'no'
    else:
      HuuUpdateHost.cimcSecureBoot = 'no'
    HuuUpdateHost.rebootCimc = rebootCimc.lower()	
	
    return True


  def HuuSuccessfullUpdateCount(self):
    return len(self.successfullUpdateList) 
	 
  def HuuFailedUpdateCount(self):
    return len(self.failedUpdateList) 

  def HuuUpdateSuccessfull(self, entry, logger):
    logger.debug('Update Successful. Adding entry and firing logout')
    entry.AaaLogout(logger)
    self.successfullUpdateList.append(entry) 

  def HuuUpdateFailed(self, entry, logger):
    logger.debug('Update Failed. Adding entry and firing logout')
    entry.AaaLogout(logger)
    self.failedUpdateList.append(entry)

  def HuuUpdateFailedEntry(self):
    try:
      entry = self.failedUpdateList.pop()
    except:
      return None
    return entry

  def HuuUpdateSuccessfullEntry(self):
    try:
      entry = self.successfullUpdateList.pop()
    except:
      return None
    return entry


# Function to process the request completion response data
def HuuProcessCompletionWork(logger, work, pendingQueue, delayQueue, firmwareUpdate):
  logger.info('Processing the completion status of a request')

  if ( work.huuUpdateState == HuuUpdateState.HUU_CATALOG_STATE_DONE):
    logger.info ("Catalog Information received. Exit")
    firmwareUpdate.HuuUpdateSuccessfull(work, logger)
    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_NONE
    work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_SUCCESSFULL
    return

  # Check if the particular request is hanging here for a long time
  if (work.updateStartTime != None):
    if ((time() - work.updateStartTime) >= int(work.updateTimeOutValue)):
      logger.error('HUU Firmware update timed out for CIMC (%s).' %(work.cimcIpAddress))
      logger.error('HUU Firmware Update Failed on server with CIMC (' + work.cimcIpAddress + ')') 
      work.huuUpdateInProgress = False
      firmwareUpdate.HuuUpdateFailed(work, logger)
      work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_NONE
      work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_FAILED
      work.updateFailureCause = 'Firmware update failed because it timed out. Check host for details.'
      print 'Firmware update failed on server with CIMC IP (%s)' %(work.cimcIpAddress)
      print
      return

  if (work.loginState & HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT):
    # Check if Login has already been retried enough times
    if (work.loginFailedCount != 0):
      work.loginRetryCount += 1
      logger.warning('Login attempt for CIMC '+ work.cimcIpAddress + ' failed %s times.' %(work.loginRetryCount))
      if (work.loginRetryCount >= 10):
        logger.error('Already tried enough to login to CIMC ' + work.cimcIpAddress + ' giving up.')
        work.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT
        work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_FAILED
        firmwareUpdate.HuuUpdateFailed(work, logger)
        work.huuUpdateInProgress = False
        work.huuHostLoggedIn = False
        print 'Firmware update failed on server with CIMC IP (%s)' %(work.cimcIpAddress)
        print
        return
      if (work.lastTaskRetriable == False):
        logger.error('Login attempt for CIMC '+ work.cimcIpAddress + ' failed with non-retriable error.')
        logger.error('HUU Firmware Update Failed on server with CIMC (' + work.cimcIpAddress + ')')
        work.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT
        work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_FAILED
        firmwareUpdate.HuuUpdateFailed(work, logger)
        work.huuUpdateInProgress = False
        work.huuHostLoggedIn = False
        print 'Firmware update failed on server with CIMC IP (%s)' %(work.cimcIpAddress)
        print
        return

    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_LOGIN
    if (work.loginRetryCount):
      work.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT
      work.loginExpired = True
      work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_LOGIN 
      # Delay the next login retry request for 60 secs
      work.delayStartTime = time()
      work.delayInterval = 60
      delayQueue.put(work)
    else:
      work.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT
      work.loginExpired = True
      work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_LOGIN 
      pendingQueue.put(work)
    return

  if (work.loginState & HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_IN):
    # Check if the CIMC login has expired
    if ((time() - (work.lastLoginTime + int(work.refreshPeriod))) > 0):
      work.loginState = HuuUpdateState.HUU_UPDATE_LOGIN_STATE_LOGGED_OUT
      work.loginExpired = True
      logger.info('Login expired for CIMC ' + work.cimcIpAddress)
      work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_LOGIN 
      pendingQueue.put(work)
      return
    # Check if the LOGIN is about the expire
    elif ((time() - (work.lastLoginTime + int(work.refreshPeriod) + 180)) > 0):
      logger.info('Time to send Login keepalive for CIMC ' + work.cimcIpAddress)
      work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_KEEPALIVE 
      pendingQueue.put(work)
      return

  if (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_INITIALIZED):
    logger.info('First check if the CIMC (' + work.cimcIpAddress + ') supports remote firmware update')
    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_REQ_FIRMWARE
    work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_REQ_FIRMWARE_STATE
    pendingQueue.put(work)


  # Process the firmware state request response
  elif (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_RCVD_FIRMWARE_STATE):
    logger.debug('Remote firmware update is supported by CIMC (' + work.cimcIpAddress + ')')
    logger.info('Initiating firmware update for server with CIMC (' + work.cimcIpAddress + ')')
    work.getFirmwareStateRetryCount = 0
    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_UPDATE_FIRMWARE
    work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_SEND_UPDATE_REQ
    pendingQueue.put(work)
  elif (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_FAILED_FIRMWARE_STATE): 
    # If the failure was a retriable, try again
    if (work.lastTaskRetriable == True):
      work.getFirmwareStateRetryCount += 1
      # Check if the update retry count exceeding limit
      if (work.getFirmwareStateRetryCount >= 5):
        logger.error('Remote firmware update is not supported by server with CIMC (' + work.cimcIpAddress + ')')
        firmwareUpdate.HuuUpdateFailed(work, logger)
        work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_NONE
        work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_NOT_SUPPORTED
      else:
        logger.debug('Retrying firmware state request on CIMC (' + work.cimcIpAddress + ')') 
        work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_REQ_FIRMWARE
        work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_REQ_FIRMWARE_STATE
        # Delay the next status request for 30 secs
        work.delayStartTime = time()
        work.delayInterval = 30
        delayQueue.put(work)
    else:
      firmwareUpdate.HuuUpdateFailed(work, logger)
      work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_NONE
      work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_NOT_SUPPORTED
      logger.error('Remote firmware update is not supported by server with CIMC (' + work.cimcIpAddress + ')')
      print 'Firmware update failed on server with CIMC IP (%s)' %(work.cimcIpAddress)
      print


  # Process the firmware update request response
  elif (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_RCVD_UPDATE_RESPONSE): 
    logger.info('HUU firmware update successfully initiated on server with CIMC (' + work.cimcIpAddress + ')')
    work.huuUpdateInProgress = True
    work.updateStartTime = time()
    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_REQ_STATUS
    work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_SEND_STATUS_REQ
    # Delay the next status request for 30 secs
    work.delayStartTime = time()
    work.delayInterval = 30
    delayQueue.put(work)
  elif (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_RESPONSE): 
    work.huuUpdateInProgress = False

    # If the failure was a retriable, try again
    if (work.lastTaskRetriable == True):
      work.updateRetryCount += 1
      # Check if the update retry count exceeding limit
      if (work.updateRetryCount >= 3):
        firmwareUpdate.HuuUpdateFailed(work, logger)
        work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_NONE
        work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_NOT_SUPPORTED
        print 'Firmware update failed on server with CIMC IP (%s)' %(work.cimcIpAddress)
        print
      else:
        logger.debug('Retrying firmware update state request on CIMC (' + work.cimcIpAddress + ')') 
        work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_UPDATE_FIRMWARE
        work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_SEND_UPDATE_REQ
        # Delay the next status request for 1 min
        work.delayStartTime = time()
        work.delayInterval = 60
        delayQueue.put(work)
    else:
      firmwareUpdate.HuuUpdateFailed(work, logger)
      work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_NONE
      work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_NOT_SUPPORTED
      print 'Firmware update failed on server with CIMC IP (%s)' %(work.cimcIpAddress)
      print


  # Process the firmware update status request response
  elif (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_FAILED_STATUS_RESPONSE): 
    logger.debug('Need to try firmware update status request again')
    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_REQ_STATUS
    work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_SEND_STATUS_REQ
    # Delay the next status request for 30 secs
    work.delayStartTime = time()
    work.delayInterval = 30
    delayQueue.put(work)
  elif (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_RCVD_STATUS_RESPONSE): 
    logger.debug('Send firmware updater request this time')
    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_REQ_UPDATER
    work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_SEND_UPDATER_REQ
    # Delay the next status request for 30 secs
    work.delayStartTime = time()
    work.delayInterval = 30
    delayQueue.put(work)

  elif (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATER_RESPONSE): 
    logger.debug('Send get updater status request again')
    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_REQ_UPDATER
    work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_SEND_UPDATER_REQ
    # Delay the next status request for 30 secs
    work.delayStartTime = time()
    work.delayInterval = 30
    delayQueue.put(work)
  elif (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_RCVD_UPDATER_RESPONSE): 
    logger.debug('Send firmware update status request this time')
    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_REQ_STATUS
    work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_SEND_STATUS_REQ
    # Delay the next status request for 1 min
    work.delayStartTime = time()
    work.delayInterval = 60
    delayQueue.put(work)


  elif (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_UPDATE_FAILED): 
    logger.error('HUU Firmware Update Failed on server with CIMC (' + work.cimcIpAddress + ')') 
    work.huuUpdateInProgress = False
    firmwareUpdate.HuuUpdateFailed(work, logger)
    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_NONE
    work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_FAILED
    print 'Firmware update failed on server with CIMC IP (%s)' %(work.cimcIpAddress)
    print
  elif (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_UPDATE_SUCCESSFULL): 
    logger.info('HUU Firmware Update Successful on server with CIMC (' + work.cimcIpAddress + ')') 
    work.huuUpdateInProgress = False
#    firmwareUpdate.HuuUpdateSuccessfull(work)
    # Restart updateStartTime so that it do not get fired now
    work.updateStartTime = time() 
    logger.debug('Send get update details request')
    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_REQ_UPDATE_DETAILS 
    work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_SEND_UPDATE_DETAILS_REQ
    work.getUpdateDetailsRetryCount = 1
    pendingQueue.put(work)

  elif (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_FAILED_UPDATE_DETAILS_RESPONSE):
    work.getUpdateDetailsRetryCount += 1
    if (work.getUpdateDetailsRetryCount >= 3):
      firmwareUpdate.HuuUpdateSuccessfull(work,logger)
      work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_NONE
      work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_SUCCESSFULL
    else:
      logger.debug('Send get update details request again')
      work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_REQ_UPDATE_DETAILS 
      work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_SEND_UPDATE_DETAILS_REQ
      # Delay the next status request for 20 secs
      work.delayStartTime = time()
      work.delayInterval = 20
      delayQueue.put(work)
  elif (work.huuUpdateState == HuuUpdateState.HUU_UPDATE_STATE_RCVD_UPDATE_DETAILS_RESPONSE): 
    firmwareUpdate.HuuUpdateSuccessfull(work, logger)
    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_NONE
    work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_SUCCESSFULL


  else:
    logger.error('Unknown state (%s), should not be here. CIMC (%s)' %(str(work.huuUpdateState), work.cimcIpAddress))
    logger.error('HUU Firmware Update Failed on server with CIMC (' + work.cimcIpAddress + ')') 
    work.huuUpdateInProgress = False
    firmwareUpdate.HuuUpdateFailed(work, logger)
    work.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_NONE
    work.huuUpdateState = HuuUpdateState.HUU_UPDATE_STATE_UPDATE_FAILED
    print 'Firmware update failed on server with CIMC IP (%s)' %(work.cimcIpAddress)
    print

  return


def HuuProcessPendingWork(logger, work):
  if (work.huuUpdateNextTask == HuuUpdateState.HUU_UPDATE_TASK_LOGIN):
    work.HuuUpdateLogin(logger)
  elif (work.huuUpdateNextTask == HuuUpdateState.HUU_UPDATE_TASK_KEEPALIVE):
    work.HuuUpdateKeepAlive(logger)
  elif (work.huuUpdateNextTask == HuuUpdateState.HUU_UPDATE_TASK_LOGOUT):
    work.HuuUpdateLogout(logger)
  elif (work.huuUpdateNextTask == HuuUpdateState.HUU_UPDATE_TASK_REQ_FIRMWARE):
    work.HuuUpdateCheckFirmware(logger)
  elif (work.huuUpdateNextTask == HuuUpdateState.HUU_UPDATE_TASK_UPDATE_FIRMWARE):
    work.HuuUpdateSendFirmwareUpdate(logger)
  elif (work.huuUpdateNextTask == HuuUpdateState.HUU_UPDATE_TASK_REQ_STATUS):
    work.HuuUpdateSendUpdateStatus(logger)
  elif (work.huuUpdateNextTask == HuuUpdateState.HUU_UPDATE_TASK_REQ_UPDATER):
    work.HuuUpdateGetUpdaterStatus(logger)
  elif (work.huuUpdateNextTask == HuuUpdateState.HUU_UPDATE_TASK_REQ_UPDATE_DETAILS):
    work.HuuUpdateGetUpdateDetails(logger)

  return work


def HuuHandleFirmwareUpdate(workQueue, completionQueue, logQueue, syncLock):

  logger = HuuProcessLoggerConfigurer(logQueue)

  needToExit = False
  while True:
    try:
      syncLock.acquire()
    except:
      logger.error('Unable to acquire the syncLock. Exiting child process (pid: %s).' %(os.getpid()))
      break;
    try:
      work = workQueue.get()
    except:
      logger.error('Exception occured. Need to exit')
      needToExit = True
    syncLock.release()    

    if (work == None or needToExit == True):
      logger.debug('Exiting child process')
      break
    logger.debug('Found an entry in the work queue')

    responseData = HuuProcessPendingWork(logger, work)

    completionQueue.put(responseData)



def main():
  global cimcUpdateDict  

  signal.signal(signal.SIGINT, HuuKeyboardInterruptHandler)
  firmwareUpdate = HuuUpdate()

  firmwareUpdate.HuuUpdateProcessCommandLineArgs(None)


  # Create the Queue for log data handling
  logQueue = multiprocessing.Queue(-1)

  # Initialize the log handler
  processName = multiprocessing.current_process().name
  logger = logging.getLogger(processName)
  logHandler = logging.handlers.RotatingFileHandler(firmwareUpdate.logFile, 'a', 500000, 10)
  logHandler.setFormatter(logFormatter)
  logger.addHandler(logHandler)
  logger.setLevel(DEFAULT_LEVEL)
#  if (firmwareUpdate.logLevel == '0'):
#    logger.setLevel(logging.CRITICAL)
#  elif (firmwareUpdate.logLevel == '1'):
#    logger.setLevel(logging.ERROR)
#  elif (firmwareUpdate.logLevel == '2'):
#    logger.setLevel(logging.WARNING)
#  elif (firmwareUpdate.logLevel == '3'):
#    logger.setLevel(logging.INFO)
#  elif (firmwareUpdate.logLevel == '4'):
#    logger.setLevel(logging.DEBUG)

  logger.info('Hello from the main process')

#Check if Generate key or Encryption options are provided.

  if (firmwareUpdate.generateKey == True ):
	if (supportCrypto == False):
		print '[Error] Cannot generate keys. Needed package unavailable. Need pycrypto >= 2.6'
	else: 
		firmwareUpdate.generateKeys(logger)
	sys.exit(0)
  if (firmwareUpdate.inFile != None ):
	if (supportCrypto == False):
		print '[Error] Cannot use encrypted password. Needed package unavailable. Need pycrypto >= 2.6'
	else: 
		firmwareUpdate.encryptFile(logger)
	sys.exit(0)

  # This thread will read from the subprocesses and write to the main log's
  # handlers.
  logQueueReader = HuuLoggerThread(logQueue, logger)
  logQueueReader.start()

  # Check if the single user option is being invoked
  if (firmwareUpdate.ipAddress == None and firmwareUpdate.remoteShareIp == None and firmwareUpdate.configFile != None):
    if (False == firmwareUpdate.HuuOpenConfigFile(logger)):
      sys.exit(0)
    if (False == firmwareUpdate.HuuUpdateProcessConfigFileData(logger)):
      print '[Error]: Processing config file data failed'
      sys.exit(0)
  else: # Single user mode being invoked
    logger.debug('[Debug]: Create entry for ' + firmwareUpdate.ipAddress)
    updateHost = HuuUpdateHost(firmwareUpdate.ipAddress, firmwareUpdate.userName,
		firmwareUpdate.password, firmwareUpdate.imageFile);
    cimcUpdateDict[firmwareUpdate.ipAddress] = updateHost

  totalNumberOfHostToUpdate = len(cimcUpdateDict)

  # Create the shared queues for multiprocess handling
  syncLock = multiprocessing.Lock()
  pendingWorkQueue = multiprocessing.Queue(-1)
  pendingCompletionQueue = multiprocessing.Queue(-1)
  delayedWorkQueue = multiprocessing.Queue(-1)

  # Create the child processes to handle the actual work. We will create as
  # many processes as there are cores in the server
  if (firmwareUpdate.dispComponentList == False ):
  	print
	print 'Total of ' + str(totalNumberOfHostToUpdate) + ' servers firmware to be updated.'
	print
  numberOfProcess = multiprocessing.cpu_count()
  if (totalNumberOfHostToUpdate < numberOfProcess):
    numberOfProcess = totalNumberOfHostToUpdate
  processList = []

  for num in range(numberOfProcess):
    p = multiprocessing.Process(target=HuuHandleFirmwareUpdate,
		args=(pendingWorkQueue, pendingCompletionQueue, logQueue, syncLock))
    processList.append(p)

  # The child processes have started. Now push work into the pending queue
  for cimcIp in cimcUpdateDict:
    updateHost = cimcUpdateDict[cimcIp]
    logger.debug('Pushing CIMC IP '+ cimcIp + ' into pending queue')
    updateHost.huuUpdateNextTask = HuuUpdateState.HUU_UPDATE_TASK_LOGIN
    pendingWorkQueue.put(updateHost) 

  if (firmwareUpdate.dispComponentList == True ):
    print 'Retriving Catalog.....'
  else:
    print 'Updating firmware.....'
  print ' '

  # Let the processes start working
  for p in processList:
    p.start()

  # The main process will wait for status in the completion queue
  notDone = True
  while notDone:
    try:
      completionWork = pendingCompletionQueue.get(True, 3)
    except Queue.Empty:
      pass
    else:
      if (completionWork != None):
        logger.debug('Found an entry in the completion queue for processing')
        HuuProcessCompletionWork(logger, completionWork, pendingWorkQueue, delayedWorkQueue, firmwareUpdate)

    # Now look into the delayedWorkQueue for any pending work
    try:
      delayWork = delayedWorkQueue.get(False) 
    except Queue.Empty:
      logger.debug('No delayed queue work item found')
    else:
      if (delayWork != None):
        if ((time() - delayWork.delayStartTime) >= delayWork.delayInterval):
          logger.debug('Process delayed queue work item')
          pendingWorkQueue.put(delayWork)
        else:
          # Put the work back in the delayed queue
          delayedWorkQueue.put(delayWork)

    # Check if all the update is done with
    if (firmwareUpdate.HuuSuccessfullUpdateCount() + firmwareUpdate.HuuFailedUpdateCount() >= totalNumberOfHostToUpdate):
      notDone = False
      if (firmwareUpdate.dispComponentList == True ): 
        logger.info('Completed Catalog process')
      else:
        logger.info('Completed update process')
      # Also make sure that all the multiprocessing Queues are empty

  # Let other process exit from the loop
  for p in processList:
    pendingWorkQueue.put(None)

  pendingWorkQueue.close()
  pendingCompletionQueue.close()

  for p in processList:
    p.join()

  
  if (firmwareUpdate.dispComponentList == True ): 
    sys.exit(0)

  print
  print 'Update Summary:'
  print '---------------'
  print

  # Display the failed update list
  if (firmwareUpdate.HuuFailedUpdateCount):
    while True:
      entry = firmwareUpdate.HuuUpdateFailedEntry()
      if (entry == None):
        break;
      print 'Firmware update failed for CIMC - %s, Reason - %s' %(entry.cimcIpAddress, entry.updateFailureCause) 

  # Display the successfull update list
  if (firmwareUpdate.HuuFailedUpdateCount):
    while True:
      entry = firmwareUpdate.HuuUpdateSuccessfullEntry()
      if (entry == None):
        break;
      print 'Firmware update successful for CIMC - %s' %(entry.cimcIpAddress) 

  # Make the logging process to exit now
  print
  logQueue.put(None)  


if __name__ == "__main__":
  main()



