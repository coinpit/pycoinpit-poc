#!/usr/bin/env python

#watch out, linux specific commands used

import binascii
import hashlib
import hmac
import json
import pybitcointools				#pip install pybitcointools -see https://github.com/vbuterin/pybitcointools
import sys
import time
import requests
import pyelliptic

#2do: post request
#answer questions in comments

class coinpit():
    "cointpit api calls -testnet"



    def __init__(self):
	"upon instantiation get server-public-key (unknown at startup) from server and calculate secret as follows"
	"ecdsa(private user key + public server key) = shared secret - used for auth (hmac secrect as header)"

	keyfile="testnetkeyfile.json"			#SPECIFY FILENAME OF YOUR KEYFILE HERE -  *.json ! download via webclient menu
	keys = json.load(open(keyfile, 'r'), 'utf8')
	self.user_pub_key=keys['publicKey']
	self.userid = keys['address']

	self.baseurl="https://live.coinpit.me"				#testnet - real net is  .io

	network_code = 0 if self.userid[0] == '1' else 111		#dont know what that represents

	headers = {
			'Authorization' : 'HMAC ' + self.userid,
			'nonce':str(long(time.time() * 100000))
			}

	try:
	    r = requests.get(self.baseurl + '/api/auth/' + self.user_pub_key, headers=headers)
	except:
	    print 'network error...'
	    sys.exit()

	server_response = json.loads(r.content, 'utf8')

	server_pub_key = server_response['serverPublicKey']

	pub_key_bytes = binascii.unhexlify(server_pub_key)

	uncompressed_user_key = binascii.unhexlify(pybitcointools.decompress(self.user_pub_key))

	uncompressed_server_key = binascii.unhexlify(pybitcointools.decompress(server_pub_key))

	user_priv_key_bin = binascii.unhexlify(pybitcointools.encode_privkey(keys['privateKey'], 'hex', network_code))

	self.user = pyelliptic.ECC(privkey=user_priv_key_bin, pubkey=uncompressed_user_key, curve='secp256k1')

	self.sharedsecret = self.user.get_ecdh_key(uncompressed_server_key)


	#print self.sharedsecret
	#print self.user_pub_key
	#print self.user



    def order(self):
	"make an api call"


	#construct url for call
	endpoint="/order" #specify wanated api in method call
	uri = '/api' + endpoint + '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.order=self.pollexchange(self.baseurl,uri)

	return (self.order)



    def orderbook(self):
	"make an api call"


	#construct url for call
	endpoint="/orderbook" #specify wanated api in method call
	uri = '/api' + endpoint + '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.orderbook=self.pollexchange(self.baseurl,uri)
	return (self.orderbook)

    def userexecution(self):
	"make an api call"

	#construct url for call
	endpoint="/userexecution" #specify wanated api in method call
	uri = '/api' + endpoint + '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.userexecution=self.pollexchange(self.baseurl,uri)
	return (self.userexecution)


    def trade(self):
	"make an api call"

	#construct url for call
	endpoint="/trade" #specify wanated api in method call
	uri = '/api' + endpoint + '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.trade=self.pollexchange(self.baseurl,uri)
	return (self.trade)


    def margin(self):
	"make an api call"
	##error: {"error":"exchange.getRequiredMarginCoverage(...)[(intermediate value)] is not a function"}

	#construct url for call
	endpoint="/margin" #specify wanated api in method call
	uri = '/api' + endpoint #+ '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.margin=self.pollexchange(self.baseurl,uri)

	return (self.margin)


    def position(self):
	"make an api call"

	#construct url for call
	endpoint="/position" #specify wanated api in method call
	uri = '/api' + endpoint #+ '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.position=self.pollexchange(self.baseurl,uri)

	return (self.position)

    def pnl(self):
	"make an api call"

	#construct url for call
	endpoint="/pnl" #specify wanated api in method call
	uri = '/api' + endpoint #+ '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.pnl=self.pollexchange(self.baseurl,uri)

	return (self.pnl)


    def withdrawtx(self):
	"make an api call"
	#call fautly, maybe post + further args required (tx adress)

	#construct url for call
	endpoint="/withdrawtx" #specify wanated api in method call
	uri = '/api' + endpoint #+ '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.withdrawtx=self.pollexchange(self.baseurl,uri)

	return (self.withdrawtx)

    def spec(self):
	"make an api call"
	#call fautly, maybe post + further args required (tx adress)

	#construct url for call
	endpoint="/spec" #specify wanated api in method call
	uri = '/api' + endpoint #+ '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.spec=self.pollexchange(self.baseurl,uri)

	return (self.spec)

    def recoverytx(self):
	"make an api call"


	#construct url for call
	endpoint="/recoverytx" #specify wanated api in method call
	uri = '/api' + endpoint #+ '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.recoverytx=self.pollexchange(self.baseurl,uri)

	return (self.recoverytx)

    def userdetails(self):
	"make an api call"


	#construct url for call
	endpoint="/userdetails" #specify wanated api in method call
	uri = '/api' + endpoint #+ '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.userdetails=self.pollexchange(self.baseurl,uri)

	return (self.userdetails)


    def error(self):
	"make an api call"
	#dont know that that does


	#construct url for call
	endpoint="/error" #specify wanated api in method call
	uri = '/api' + endpoint #+ '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.error=self.pollexchange(self.baseurl,uri)

	return (self.error)


    def info(self):
	"make an api call"
	#dont know that that does


	#construct url for call
	endpoint="/info" #specify wanated api in method call
	uri = '/api' + endpoint #+ '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.info=self.pollexchange(self.baseurl,uri)

	return (self.info)

    def config(self):
	"make an api call"
	#dont know that that does


	#construct url for call
	endpoint="/config" #specify wanated api in method call
	uri = '/api' + endpoint #+ '?instrument=BTC1'		#dont know what instruments are possible and why btc1 not btc

	self.config=self.pollexchange(self.baseurl,uri)

	return (self.config)


    def pollexchange(self,baseurl,uri):

	self.nonce = str(long(time.time() * 1000))		#calculate a nonce, server requests server time from client as nonce
							#consecutive api calls should always have excat server time, use ntp
	mac = hmac.new(self.sharedsecret, '{"method":"GET","uri":"' + uri + '","nonce":'+ self.nonce +'}', hashlib.sha256)
	sig = mac.hexdigest()

        #print 'json', '{"method":"GET","uri":"' + uri + '","nonce":'+ nonce +'}'		#debug
	#print 'sig', sig								#debug

	headers = {
	    'Authorization' : 'HMAC ' + self.userid + ':' + sig,
	    'nonce':self.nonce,
	    'Accept': 'application/json'
	    }

        #try:
        r = requests.get(self.baseurl + uri, headers=headers)
        #except:
        #print 'network error...'
        #sys.exit()


	return(r.content)





instanz=coinpit()		#call instance
#print instanz.order()		#make an api call 'order' and print result
#print''
#print instanz.orderbook()	#api call orderbook
#print ''
#print instanz.userexecution()
#print ''
#print instanz.trade()
#print ''
#print instanz.margin()
#print ''
#print instanz.position()
#print ''
#print instanz.pnl()
#print ''
#print instanz.withdrawtx()
#print ''
#print instanz.spec()
#print ''
#print instanz.recoverytx()
#print ''
#print instanz.userdetails()
#print ''
#print instanz.userdetails()
#print ''
#print instanz.info()
print ''
print instanz.config()
pass



#valid api call list accroding to https://live.coinpit.me/api
#
#{
#"/api/auth/:publicKey":["get"],
#"/api/":["get"],
#"/api/chart/:tf":["get"],						#what is tf?
#"/api/order":["get","post","put","delete"],
#"/api/order/:id":["get","delete"],
#"/api/closedorder":["get"],
#"/api/closedorder/:uuid":["get"],
#"/api/cancelledorder":["get"],
#"/api/cancelledorder/:uuid":["get"],
#"/api/orderbook":["get"],
#"/api/userexecution":["get"],
#"/api/userexecution/:uuid":["get"],
#"/api/trade":["get"],
#"/api/margin":["get","post"],
#"/api/margin/:amount":["delete"],
#"/api/auth":["post"],
#"/api/position":["get"],
#"/api/pnl":["get"],
#"/api/withdrawtx":["post"],
#"/api/spec":["get"],
#"/api/recoverytx":["get"],
#"/api/userdetails":["get"],
#"/api/error/:uuid":["get"],
#"/api/info":["get"],
#"/api/config":["get"]}
