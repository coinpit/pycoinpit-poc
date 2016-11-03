#!/usr/bin/env python
import binascii
import hashlib
import hmac
import json
import pybitcointools
import sys
import time
import requests
import pyelliptic

filename = sys.argv[1]
endpoint = sys.argv[2] if len(sys.argv) > 2 else '/order'
uri = '/api' + endpoint + '?instrument=BTC1'
keys = json.load(open(filename, 'r'), 'utf8')

user_pub_key=keys['publicKey']
userid = keys['address']
baseurl= "https://live.coinpit.io" if userid[0] == '1' else "http://localhost:9000"

headers = {
    'Authorization' : 'HMAC ' + userid,
    'nonce':str(long(time.time() * 100000))
}

r = requests.get(baseurl + '/api/auth/' + keys['publicKey'], headers=headers)
server_response = json.loads(r.content, 'utf8')
server_pub_key = server_response['serverPublicKey']
pub_key_bytes = binascii.unhexlify(server_pub_key)

uncompressed_user_key = binascii.unhexlify(pybitcointools.decompress(user_pub_key))
uncompressed_server_key = binascii.unhexlify(pybitcointools.decompress(server_pub_key))

user_priv_key_bin = binascii.unhexlify(pybitcointools.encode_privkey(keys['privateKey'], 'hex', 111))

user = pyelliptic.ECC(privkey=user_priv_key_bin, pubkey=uncompressed_user_key, curve='secp256k1')

sharedsecret = user.get_ecdh_key(uncompressed_server_key)

nonce = str(long(time.time() * 1000))
mac = hmac.new(sharedsecret, '{"method":"GET","uri":"' + uri + '","nonce":'+ nonce +'}', hashlib.sha256)
sig = mac.hexdigest()
print 'json', '{"method":"GET","uri":"' + uri + '","nonce":'+ nonce +'}'
print 'sig', sig

headers = {
    'Authorization' : 'HMAC ' + userid + ':' + sig,
    'nonce':nonce,
    'Accept': 'application/json'
}
r = requests.get(baseurl + uri, headers=headers)
print r.content
