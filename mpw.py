#!/usr/bin/env python3

from doctest import master
import getopt
import site
import sys

import scrypt
import hmac
import hashlib

verbose = False

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

def generate_masterkey(masterpass, name):
  global verbose

  key = masterpass.encode()
  scope = 'com.lyndir.masterpassword'
  seed = scope.encode() + LEN(name.encode()) + name.encode()

  if verbose: print('masterPassword.id: ' + hex_log(key))
  if verbose: print('masterKeySalt.id: ' + hex_log(seed))

  N = 32768
  r = 8
  p = 2
  dkLen = 64

  return scrypt.hash(key, seed, N, r, p, dkLen)

def generate_sitekey(key, site_name, site_counter=1):
  global verbose

  scope = 'com.lyndir.masterpassword'
  seed = scope.encode() + LEN(site_name.encode()) + site_name.encode() + site_counter.to_bytes(4,'big')
  # message = seed.encode()

  if verbose: print('siteSalt.id: ' + hex_log(seed))

  return hmac.new(key, seed, hashlib.sha256).digest()

def generate_password(site_key, template):
  global verbose

  pass_word = ''

  for i, t in enumerate(template):
    pass_chars = template_chars[template[i]]
    pass_char = pass_chars[int(site_key[i+1]) % len(pass_chars)]
    if verbose: print(f"  - class: {t}, index: {site_key[i+1]:3} (0x{site_key[i+1]:02x}) => character: {pass_char}")
    pass_word += pass_char

  return pass_word

def main():
  global verbose

  argv = sys.argv[1:]

  opts, args = getopt.getopt(argv, 'u:U:m:M:t:T:P:c:a:p:C:f:F:R:vqh')

  name = 'test'
  masterpass = 'test'
  siteName = 'test'
  siteCounter = 1
  templates = template_class['long']

  for o, a in opts:
    if o == "-h":
      usage()
      exit(0)
    elif o == "-v":
      verbose = True
    elif o == "-u":
      name = a
    elif o == "-M":
      masterpass = a
    elif o == "-t":
      if a not in template_class.keys():
        sys.stderr.write("ERROR: Unknown template class " + a + "\n")
        exit(1)
      else:
        templates = template_class[a]
    elif o == "-c":
      try:
        siteCounter = int(a)
      except ValueError:
        sys.stderr.write("ERROR: Site counter is not a number " + a + "\n")
        exit(1)       
    else:
      sys.stderr.write('ERROR: Unrecognized option ' + o + "\n")
      exit(1)

  if verbose:
    print(opts)
    print(args)

  if args:
    siteName = args[0]

  masterKey = generate_masterkey(masterpass, name)

  if verbose: print('masterKey.id: ' + hex_log(masterKey))

  siteKey = generate_sitekey(masterKey, siteName, siteCounter)

  if verbose: print('siteKey.id: ' + hex_log(siteKey))

  template = templates[ siteKey[0] % len(templates)]

  if verbose: print(f"template: {siteKey[0]} => {template}")

  pass_word = generate_password(siteKey, template)

  print(f"  => password: {pass_word}")

if __name__ == "__main__":
  main()