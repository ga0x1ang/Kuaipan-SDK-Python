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

app_name = ''
consumer_key = ''
consumer_secret = ''
oauth_token = ''
oauth_token_secret = ''
oauth_verifier = ''

root = 'app_folder' #app_folder or kuaipan
filename = ''

# define the version of api
# used in some URLs
#
API_VERSION = '1'

# define the URL and HTTP method of API
# (not fully listed)
#
API_REQUEST_TOKEN = {
    'http_method': 'GET',
    'url': 'https://openapi.kuaipan.cn/open/requestToken'
}
API_AUTHORIZE = {
    'http_method': 'POST',
    'url': 'https://www.kuaipan.cn/api.php?ac=open&op=authorisecheck'
}
API_ACCESS_TOKEN = {
    'http_method': 'GET',
    'url': 'https://openapi.kuaipan.cn/open/accessToken'
}
API_ACCOUNT_INFO = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/account_info'
    
}
API_METADATA = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/metadata/' + root + '/'
}
API_SHARES = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/shares/' + root + '/'
} 
API_CREATE_FOLDER = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/fileops/create_folder'
}
API_DELETE = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/fileops/delete'
}
API_MOVE = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/fileops/move'
}
API_COPY = {
    'http_method': 'GET',
    'url': 'http://openapi.kuaipan.cn/' + API_VERSION + '/fileops/copy'
}
API_UPLOAD_LOCATE = {
    'http_method': 'GET',
    'url': 'http://api-content.dfs.kuaipan.cn/' + API_VERSION + '/fileops/upload_locate'
}
API_UPLOAD_FILE = {
    'http_method': 'POST',
    'url': '/' + API_VERSION + '/fileops/upload_file'
}
API_DOWNLOAD_FILE = {
    'http_method': 'GET',
    'url': 'http://api-content.dfs.kuaipan.cn/' + API_VERSION + '/fileops/download_file'
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

def ParseJSON(data):
    ret = json.loads(data)
    return ret

# used by CallAPI()
# http request and response , return a unicode dict, need to str() before use
#
def Req(http_method, url, postdata):
    if(http_method == 'GET'):
        response = requests.get(url)
    elif(http_method == 'POST'):
        response = requests.post(url, postdata)

    # return the data as a dict
    ret = response.content
    return ret

# used by all API calls
# the 'param' parameter is a dict() 
# we will add a callback parameters in the future
#
def CallAPI(api, data):
    http_method = api['http_method']
    url = api['url']
    
    print url

    if(http_method == 'POST'):
        ret = Req(http_method, url, data)
    elif(http_method == 'GET'):
        request_url = GenReqStr(url, data)
        signature = GenSignature(http_method, request_url, consumer_secret, oauth_token_secret)
        request_url += 'oauth_signature=' + signature
        ret = Req(http_method, request_url, '')

    return ret

# get temperory token and token_secret
#
def RequestToken():
    data = CallAPI(API_REQUEST_TOKEN, {})
    ret = ParseJSON(data)

    return ret

# get the oauth_verifier used for AccessToken()
# this is a tricky implementation, need to be fixed
#
def Authorize(appname, username, password):
    param = {'oauth_token': oauth_token, 'username': username, 'userpwd': password, 'app_name': appname}
    data = CallAPI(API_AUTHORIZE, param)
    # tricks to get the oauth_verifier
    start = data.find('<strong>') + 8
    end = data.find('</strong>')
    ret = data[start:end]

    return ret

# get access token ( by using previously got temperory token)
# return a page = = maybe we need to do some tricks to retrive the oauth_verifier
def GetAccessToken():
    param = {'oauth_token': oauth_token, 'oauth_verifier': oauth_verifier}
    data = CallAPI(API_ACCESS_TOKEN, param)
    ret = ParseJSON(data)

    return ret

#
#
def GetAccountInfo():
    param = {'oauth_token': oauth_token}
    data = CallAPI(API_ACCOUNT_INFO, param)
    ret = ParseJSON(data)
    
    return ret

#
# more parameters should be available to users to be tuned 
def GetMetadata(filename):
    API_METADATA['url'] += filename
    
    param = {'oauth_token': oauth_token}
    data = CallAPI(API_METADATA, param)
    ret = ParseJSON(data)
    
    return ret

#
# 
def Shares(filename):
    API_SHARES['url'] += filename
    
    param = {'oauth_token': oauth_token}
    data = CallAPI(API_SHARES, param)
    ret = ParseJSON(data)
    
    return ret

#
#
def Create(filename):    
    param = {'oauth_token': oauth_token, 'root': root, 'path': filename}
    data = CallAPI(API_CREATE_FOLDER, param)
    ret = ParseJSON(data)
    
    return ret

#
#
def Delete(filename):    
    param = {'oauth_token': oauth_token, 'root': root, 'path': filename}
    data = CallAPI(API_DELETE, param)
    ret = ParseJSON(data)
    
    return ret

#
#
def Move(src, dest):    
    param = {'oauth_token': oauth_token, 'root': root, 'from_path': src, 'to_path': dest}
    data = CallAPI(API_MOVE, param)
    ret = ParseJSON(data)
    
    return ret

#
#
def Copy(src, dest):    
    param = {'oauth_token': oauth_token, 'root': root, 'from_path': src, 'to_path': dest}
    data = CallAPI(API_COPY, param)
    ret = ParseJSON(data)
    
    return ret

#
#
def GetUploadURL(ip):
    if(ip == ''):
        param = {'oauth_token': oauth_token}
    else:
        param = {'oauth_token': oauth_token, 'source_ip': ip} 
    data = CallAPI(API_UPLOAD_LOCATE, param)
    ret = ParseJSON(data)
    
    return ret

#
#
#def Upload(ip, overwrite, file, filename):
#    url = GetUploadURL(ip)
#    url += API_UPLOAD_FILE['url']
#    http_method = API_UPLOAD_FILE['http_method']
    
#    param = {'oauth_token': oauth_token, 'overwrite': overwrite, 'file': file}
    
#    data = 

def Download(filename):
    param = {'oauth_token': oauth_token, 'root': root, 'path': filename}
    data = CallAPI(API_DOWNLOAD_FILE, param)
    
    return data

def test():
    global oauth_token
    global oauth_token_secret
    global charged_dir
    #global oauth_verifier

    data = RequestToken()
    print data
    oauth_token = str(data['oauth_token'])
    oauth_token_secret = str(data['oauth_token_secret'])
    
    oauth_verifier = str(Authorize(app_name, 'patriot7@live.cn', 'a55n0lE?')) # username and password shoule be retrived by user input
    print oauth_verifier
    
    data = GetAccessToken()
    oauth_token = str(data['oauth_token'])
    oauth_token_secret = str(data['oauth_token_secret'])
    user_id = str(data['user_id'])
    charged_dir = str(data['charged_dir'])
    
    data = GetAccountInfo()
    print data
    
    data = GetMetadata('kuaipan.file')
    print data
    
    data = Shares('kuaipan.file')
    print data
    
    data = Create('delete/')
    print data
    
    data = Move('kuaipan.file', 'kuaipan.anotherfile')
    print data
    
    data = Copy('kuaipan.anotherfile', 'kuaipan.copy')
    print data
    
    data = Delete('kuaipan.anotherfile')
    print data
    
    data = GetUploadURL('')
    print data
    
    data = Download('kuaipan.copy')
    print data
