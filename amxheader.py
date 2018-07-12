# These are java classes, being imported using python syntax (Jython magic)
from burp import IBurpExtender
from burp import IHttpListener
import hmac
import hashlib
import codecs
import json
import datetime,time
import base64
import urllib
import json

# These are plain old python modules, from the standard library
# (or from the "Folder for loading modules" in Burp&gt;Extender&gt;Options)
from datetime import datetime
 
class BurpExtender(IBurpExtender, IHttpListener):
 
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Add amx header")
        callbacks.registerHttpListener(self)
        return
 
    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        # only process requests
        if not messageIsRequest:
            return
        #request = currentRequest.getRequest() 
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        timestamp = datetime.now()
        print("Intercepting message at:", timestamp.isoformat())
        bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]
        bodyStr = self._helpers.bytesToString(bodyBytes)
        appid=''    
        apikey=''
        method=requestInfo.getMethod()
        url=str(requestInfo.getUrl())
        request_content_base64_string=str(base64.b64encode(hashlib.md5(bodyStr.encode("utf")).digest()))
        unixtime = int(time.mktime(timestamp.timetuple()))
        nonce = '4d921d27136c4917ya2f459fd785d067'

        url=self._helpers.urlEncode(url)
        url=url.replace("/","%2f")
        url=url.replace("%3a443","")
        
        signature_body=appid+method+url.lower()+str(unixtime)+nonce+request_content_base64_string
        hm = hmac.new(base64.b64decode(apikey), signature_body.encode('UTF-8'), hashlib.sha256)
        signature_hmac=base64.b64encode(codecs.decode(hm.hexdigest(), 'hex'))
        auth='amx '+appid+':'+str(signature_hmac)+':'+nonce+':'+str(unixtime)
        headers = requestInfo.getHeaders()
        newHeaders = list(headers) #it's a Java arraylist; get a python list
        newHeaders.append("Authorization: " + auth)

        newMessage = self._helpers.buildHttpMessage(newHeaders, bodyStr)
         
        print("Sending modified message:")
        print("----------------------------------------------")
        print(self._helpers.bytesToString(newMessage))
        print("----------------------------------------------\n\n")
         
        currentRequest.setRequest(newMessage)
        return