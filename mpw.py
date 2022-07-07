import scrypt
import hmac
import hashlib

def LEN(x):
  return len(x).to_bytes(4,'big')

def hex_log(x):
  return(hashlib.sha256(x).hexdigest())

name = 'tesẗ'.encode()
masterpass = 'ẗest'

key = masterpass.encode()
scope = 'com.lyndir.masterpassword'
seed = scope.encode() + LEN(name) + name

print('masterPassword.id: ' + hex_log(key))
print('masterKeySalt.id: ' + hex_log(seed))

N = 32768
r = 8
p = 2
dkLen = 64

masterKey = scrypt.hash(key, seed, N, r, p, dkLen)

print('masterKey.id: ' + hex_log(masterKey))

siteName = 'ẗesẗ'.encode()
siteCounter = int(1).to_bytes(4,'big')

key = masterKey
seed = scope.encode() + LEN(siteName) + siteName + siteCounter
# message = seed.encode()

print('siteSalt.id: ' + hex_log(seed))

siteKey = hmac.new(key, seed, hashlib.sha256).digest()

print('siteKey.id: ' + hex_log(siteKey))

templates_long = [
  'CvcvnoCvcvCvcv',
  'CvcvCvcvnoCvcv',
  'CvcvCvcvCvcvno',
  'CvccnoCvcvCvcv',
  'CvccCvcvnoCvcv',
  'CvccCvcvCvcvno',
  'CvcvnoCvccCvcv',
  'CvcvCvccnoCvcv',
  'CvcvCvccCvcvno',
  'CvcvnoCvcvCvcc',
  'CvcvCvcvnoCvcc',
  'CvcvCvcvCvccno',
  'CvccnoCvccCvcv',
  'CvccCvccnoCvcv',
  'CvccCvccCvcvno',
  'CvcvnoCvccCvcc',
  'CvcvCvccnoCvcc',
  'CvcvCvccCvccno',
  'CvccnoCvcvCvcc',
  'CvccCvcvnoCvcc',
  'CvccCvcvCvccno',
]

template_chars = {
  'V': 'AEIOU',
  'C': 'BCDFGHJKLMNPQRSTVWXYZ',
  'v': 'aeiou',
  'c': 'bcdfghjklmnpqrstvwxyz',
  'A': 'AEIOUBCDFGHJKLMNPQRSTVWXYZ',
  'a': 'AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz',
  'n': '123456789',
  'o': "@&%?,=[]_:-+*$#!'^~;()/.",
  'X': "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
}

template = templates_long[ siteKey[0] % len(templates_long)]

print(f"template: {siteKey[0]} => {template}")

pass_word = ''

for i, t in enumerate(template):
  pass_chars = template_chars[template[i]]
  pass_char = pass_chars[int(siteKey[i+1]) % len(pass_chars)]
  print(f"  - class: {t}, index: {siteKey[i+1]:3} (0x{siteKey[i+1]:02x}) => character: {pass_char}")
  pass_word += pass_char

print(f"  => password: {pass_word}")