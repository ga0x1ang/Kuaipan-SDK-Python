from random import randint
from urllib import quote, urlencode, urlopen
from urlparse import parse_qsl, urlsplit, urlunsplit
import base64
import binascii
import hashlib
import hmac
import json
import random
import requests
import string
import time

consumer_key = 'xcpFXnjDjb1b8QHJ'
consumer_secret = 'Stn7uJjh3l4pTcTn'
oauth_token = ''
oauth_token_secret = ''
oauth_verifier = ''

# define the version of api
# used in some URLs
#
API_VERSION = '1'

# define the URL and HTTP method of API
# (not fully listed)
#
API_REQUEST_TOKEN = {
    'http_method': 'GET',
    'url': 'https://openapi.kuaipan.cn/open/requestToken',
    'param': {}
}
API_AUTHORIZE = {
    'http_method': 'GET',
    'url': 'https://www.kuaipan.cn/api.php',
    'param': {'oauth_token': oauth_token, 'ac': 'open', 'op': 'authorise'}
}
API_ACCESS_TOKEN = {
    'http_method': 'GET',
    'url': 'https://openapi.kuaipan.cn/open/accessToken',
    'param': {'oauth_token': oauth_token, 'oauth_verifier': oauth_verifier}
}
API_ACCOUNT_INFO = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/account_info',
    'param': {'oauth_token': oauth_token}
    
}
API_METADATA = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/metadata/',
    'param': {'oauth_token': oauth_token} # + <root>/<path>
}
API_SHARES = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/shares/',
    'param': {'oauth_token': oauth_token}  # + <root>/<path>
} 
API_CREATE_FOLDER = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/fileops/create_folder',
    'param': {'oauth_token': oauth_token}
}
API_DELETE = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/fileops/delete',
    'param': {'oauth_token': oauth_token}
}
API_MOVE = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/fileops/move',
    'param': {'oauth_token': oauth_token}
}
API_COPY = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/fileops/copy',
    'param': {'oauth_token': oauth_token}
}
API_UPLOAD_LOCATE = {
    'http_method': 'GET',
    'url': 'http://api-content.dfs.kuaipan.cn/' + API_VERSION + '/fileops/upload_locate',
    'param': {'oauth_token': oauth_token}
}
API_DOWNLOAD_FILE = {
    'http_method': 'GET',
    'url': 'http://api-content.dfs.kuaipan.cn/' + API_VERSION + '/fileops/download_file',
    'param': {'oauth_token': oauth_token}
}

#############################################################
#  some utility functions used to generate value for param  #
#############################################################

# used by oauth_timestamp parameter
# generate current timestamp string
#
def GenTimeStamp():
    return str(int(time.time()));

# used by oauth_nonce parameter
# generate a nonce value which is a string with 12 characters [a-z, A-Z, 0-9]
#
def GenNonce():
    nonce = ''
    for i in xrange(12):
        nonce += random.choice(string.letters + string.digits)
    return nonce

# common parameters used by all request
# we have to make sure the GenTimeStamp() and GenNonce() are revoked every time
def GetCommonParam():
    return {
        'oauth_consumer_key': consumer_key, # input your consumer key here
        'oauth_signature_method': 'HMAC-SHA1', # an optional parameter, could be removed?
        'oauth_timestamp': GenTimeStamp(),
        'oauth_nonce': GenNonce(),
        'oauth_version': '1.0'
    }

###############################################################
#  some basic utility functions used to operate with the API  #
###############################################################

# used in GenBaseString()
# encode url in customized rule
#
def URLencode(url):
    return quote(url, '., -, _, ~')

# used in GenSignature()
# generate the base string 
# http_method = "GET" or "POST"
# maybe we could change it to GenBaseString(http_method, url, params)? #
def GenBaseString(http_method, url):
    # parse the url, !!!!!!!!!!NEED TO BE OPTIMIZED!!!!!!!
    #
    # parse the url into several parts
    parsed_url = urlsplit(url)

    # get the parts needed and unparse them into a base uri
    base_uri = tuple()
    base_uri = parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', ''
    base_uri = urlunsplit(base_uri)

    # parse the parameters
    params = parse_qsl(parsed_url.query)
    parameters = ''
    if(params):
        params = sorted(params)
        param_list = list()
        for k, v in params:
            param = URLencode(k) + '=' + URLencode(v)
            param_list.append(param)
        parameters = '&'.join(param_list)

    # calculate the base string
    base_string = http_method + '&' + URLencode(base_uri) + '&' + URLencode(parameters)

    return base_string

# used in every request to API
# generate a signature based on the url accessed
#
def GenSignature(http_method, url, consumer_secret, token_secret):
    key = consumer_secret + '&' + token_secret
    base_string = GenBaseString(http_method, url)
    signature = quote(base64.b64encode(hmac.new(key, base_string, hashlib.sha1).digest()))

    return signature

# used in GenSignature(), but the result could also be used by requests.get() without give it  sencond parameter  
# generate the parameter part includes all parameters except oauth_signature
#
def GenReqStr(url, param):
    common_param = GetCommonParam()
    # prepare a string
    parameters = ''
    # combine the common param and other parama
    params = dict(common_param.items() + param.items())
    # iterate the params' values and output the parameter part of the request string
    for k, v in params.iteritems():
        parameter = k + '=' + v + '&'
        parameters += parameter
    # combine the url and the parameters
    request_url = url + '?' + parameters
    
    return request_url

# used by CallAPI()
# http request and response , return a unicode dict, need to str() before use
#
def Req(http_method, url):
    response = requests.get(url).raw
    data = json.load(response)

    return data

# used by all API calls
# we will add a callback parameters in the future
#
def CallAPI(api, op_param):
    http_method = api['http_method']
    url = api['url']
    param = api['param']

    request_url = GenReqStr(url, param)
    signature = GenSignature(http_method, request_url, consumer_secret, oauth_token_secret)
    request_url += 'oauth_signature=' + signature
    ret = Req('GET', request_url)

    return ret

# get temperory token and token_secret
#
def RequestToken():
    result = CallAPI(API_REQUEST_TOKEN, '')
    #return result['oauth_token'], result['oauth_token_secret']
    return result

# get the oauth_verifier used for 
#
def Authorize():
    result = CallAPI(API_AUTHORIZE, '')

    return result['oauth_verifier']

# get access token ( by using previously got temperory token)
#
def AccessToken():
    result = CallAPI(API_ACCESS_TOKEN, '')
    #return result['oauth_token'], result['oauth_token_secret']
    return result

def GetToken():
    global oauth_token
    global oauth_token_secret

    ret = RequestToken()
    oauth_token = str(ret['oauth_token'])
    print oauth_token + '\n'
    oauth_token_secret = str(ret['oauth_token_secret'])
    oauth_verifier = Authorize()
    ret = AccessToken()
    oauth_token = str(ret['oauth_token'])
    print oauth_token + '\n'
    oauth_token_secret = str(ret['oauth_token_secret'])