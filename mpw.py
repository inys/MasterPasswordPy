import getopt
import sys

import scrypt
import hmac
import hashlib

key_scopes = {
  'authentication': 'com.lyndir.masterpassword',
  'identification': 'com.lyndir.masterpassword.login',
  'recovery': 'com.lyndir.masterpassword.answer'
}

templates_maximum = [
  'anoxxxxxxxxxxxxxxxxx',
  'axxxxxxxxxxxxxxxxxno'
]

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

templates_medium = [
  'CvcnoCvc',
  'CvcCvcno'
]

templates_short = [
  'Cvcn'
]

templates_basic = [
  'aaanaaan',
  'aaannaaa',
  'aannaaan'
]

templates_pin = [
  'nnnn'
]

template_class = {
  'maximum': templates_maximum,
  'long': templates_long,
  'medium': templates_medium,
  'short': templates_short,
  'basic': templates_basic,
  'pin': templates_pin
}

template_chars = {
  'V': 'AEIOU',
  'C': 'BCDFGHJKLMNPQRSTVWXYZ',
  'v': 'aeiou',
  'c': 'bcdfghjklmnpqrstvwxyz',
  'A': 'AEIOUBCDFGHJKLMNPQRSTVWXYZ',
  'a': 'AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz',
  'n': '0123456789',
  'o': "@&%?,=[]_:-+*$#!'^~;()/.",
  'x': "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
}

def LEN(x):
  return len(x).to_bytes(4,'big')

def hex_log(x):
  return(hashlib.sha256(x).hexdigest())

def usage():
  pass

def main():

  argv = sys.argv[1:]

  opts, args = getopt.getopt(argv, 'u:U:m:M:t:P:c:a:p:C:f:F:R:vqh')

  name = 'test'
  masterpass = 'test'
  siteName = 'test'
  siteCounter = 1
  verbose = False
  templates = template_class['long']

  for o, a in opts:
    if o == "-v":
      verbose = True
    elif o == "-u":
      name = a
    elif o == "-M":
      masterpass = a
    elif o == "-c":
      siteCounter = a
    elif o == "-t":
      templates = template_class[a]
    else:
      print('unrecognized option: ' + o)

  if args:
    siteName = args[0]

  key = masterpass.encode()
  scope = 'com.lyndir.masterpassword'
  seed = scope.encode() + LEN(name.encode()) + name.encode()

  if verbose: print('masterPassword.id: ' + hex_log(key))
  if verbose: print('masterKeySalt.id: ' + hex_log(seed))

  N = 32768
  r = 8
  p = 2
  dkLen = 64

  masterKey = scrypt.hash(key, seed, N, r, p, dkLen)

  if verbose: print('masterKey.id: ' + hex_log(masterKey))

  key = masterKey
  seed = scope.encode() + LEN(siteName.encode()) + siteName.encode() + int(siteCounter).to_bytes(4,'big')
  # message = seed.encode()

  if verbose: print('siteSalt.id: ' + hex_log(seed))

  siteKey = hmac.new(key, seed, hashlib.sha256).digest()

  if verbose: print('siteKey.id: ' + hex_log(siteKey))

  template = templates[ siteKey[0] % len(templates)]

  if verbose: print(f"template: {siteKey[0]} => {template}")

  pass_word = ''

  for i, t in enumerate(template):
    pass_chars = template_chars[template[i]]
    pass_char = pass_chars[int(siteKey[i+1]) % len(pass_chars)]
    if verbose: print(f"  - class: {t}, index: {siteKey[i+1]:3} (0x{siteKey[i+1]:02x}) => character: {pass_char}")
    pass_word += pass_char

  print(f"  => password: {pass_word}")

if __name__ == "__main__":
  main()