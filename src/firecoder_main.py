#!/usr/bin/python
# -*- coding: utf-8 -*-
# Cyan's FireCoder - A CYANITE PROJECT

version = "3.0.0"

# Imports
import os
import re
import sys
import time
import base64
import string
import random
import hashlib
import argparse

# Variables
r = random.Random()
start =time.time()

# Command line stuffs
arg = argparse.ArgumentParser(description="Encodes/Decodes messages and files - requires [-I | -i] [-e | -d] [-p PASSWORD]")
conf = arg.add_mutually_exclusive_group()
conf2 = arg.add_mutually_exclusive_group()
conf3 = arg.add_mutually_exclusive_group()
conf2.add_argument("-I",  metavar=("FILENAME"), help="specify the file to encrypt", default=None)
conf2.add_argument("-i",  metavar=("MESSAGE"), help="specify the message to encrypt", default=None)
conf.add_argument("-e", help="specify use encode mode", action="store_true")
conf.add_argument("-d", help="specify use decode mode", action="store_true")
conf3.add_argument("-O", metavar=("OUTPUT"), help="sets the output file", default=None)
conf3.add_argument("-o", help="prints output to console", action="store_true")
arg.add_argument("--salt", help="add a custom salt to encryption - this will be used in places other than hashing", default=False)
arg.add_argument("--remove", help="deletes the input file after compleation", action="store_true")
arg.add_argument("--echo", help="prints extra info including the current password and HASH in plain text", action="store_true")
arg.add_argument("--debug", help="enables debug mode: this attemps to backtrack the encrption at each step to make sure decryption is possible", action="store_true")
arg.add_argument("-p", metavar=("PASSWORD"), help="specify the password for the encryption", default=None)
args = arg.parse_args()

# Title, Help & Exit if no arguments are passed
if len(sys.argv)==1:
	print("===== Cyan's FireCoder v%s - A Cyanite Project =====\n" % version)
	arg.print_help()
	sys.exit(1)


# Here we check if we are missing anything, check argument compatibility, and do some setup for missing arguments
def argumentChecker():

	# Check Password
	if args.p == None:
		arg.error("no password provided [-p PASSWORD]")
		sys.exit(1) #Exit with minor error

	# Sets Salt to reverse-Password if empty.
	if args.salt == False:
		args.salt = args.p[::-1]

	# Check if input was provided
	if args.i == None:
		if args.I == None:
			arg.error("no input provided [-I | -i]")
			sys.exit(1) #Exit with minor error
		if os.path.isfile(args.I) == False: # Check if inputfile exists
			arg.error("the input file does not exist")
			sys.exit(1) #Exit with minor error
	else:
		if args.remove:
			arg.error("you cannot use --del with -i")
			sys.exit(1) #Exit with minor error

	# Check mode
	if not args.e:
		if not args.d:
			arg.error("no mode provided [-e | -d]")
			sys.exit(1) #Exit with minor error

argumentChecker() # Run the function we just created. We only created it for organazation

# These messages will be printed if --echo is passed
def debug(message="Default text"):
	if args.echo:
		print(message)

# Utilities
def debugexit():
	print("[!!DEBUG EXIT!!]")
	sys.exit(2)

def percentage(part, whole): # Used for the loading bars in the debug output
	return 100 * float(part)/float(whole)

# Link START!!! :D
if args.o:
	print("===== Cyan's FireCoder v%s - A Cyanite Project =====\n" % version) # Title echo

# Debug mode?
debug(">> Debug ON <<\nOutput:")
if not args.e:
	debug(">Mode: Decode")
else:
	debug(">Mode: Encode")

# Password Hashing - Its Overkill, I know.
ppw1 = hashlib.sha256(args.salt.encode()).hexdigest()
ppw2 = hashlib.sha256(args.salt[::-1].encode()).hexdigest()
psa = hashlib.sha256((ppw1[::-1]+args.p+ppw2).encode()).hexdigest()

#Password echo
debug(">Password: %s\n>Salt: %s\n>HASH: %s" % (args.p,args.salt,psa)) # Print Debug info

# This is for the dictionary generators
debug(">Loading generation variables..") # Print Debug info
l = (string.digits +
	string.ascii_letters +
	string.punctuation.replace('"','')
		.replace("'",'')
		.replace("[",'')
		.replace("]",'')
		.replace("{",'')
		.replace("}",'')
		.replace("(",'')
		.replace(")",''))
l2 = [i for i in l]

debug(">Done.") # Print Debug info


# Modifiers
def replace_all(string, dic):
	return ''.join(dic.get(char, char) for char in string)

'''
def replace_all(n,t,d):
	if n == 0:
		t = ''.join(d[s] if s in d else s for s in t)
	elif n == 1:
		t=[t[i:i+2] for i in range(0, len(t), 2)]
		t = ''.join(d[s] if s in d else s for s in t)
	else:
		sys.exit(2) # Exit with major error
	return t
'''

def gen_keys(char,HASH,mode=True):
	r.seed(hashlib.sha1((char+HASH).encode()).hexdigest())
	m,d = [],{}
	for i in l:
		c = r.choice(l)
		while c in m:
			c = r.choice(l)
		m.append(c)
		if mode:
			d[i] = c
		else:
			d[c] = i
	return d

def seed_en(char,HASH): # For swopping around the codes
	return gen_keys(char,HASH,True)

def seed_de(char,HASH): # For swopping back around the codes
	return gen_keys(char,HASH,False)

def scram_en(string):
		l = list(string)
		r.seed(hashlib.sha1(psa.encode()).hexdigest())
		r.shuffle(l)
		return ''.join(l)

def scram_de(string):
	l = list(string)
	l2 = list(range(len(l)))
	r.seed(hashlib.sha1(psa.encode()).hexdigest())
	r.shuffle(l2)
	l3 = [0]*len(l)
	for index,originalIndex in enumerate(l2):
		l3[originalIndex] = l[index]
	return ''.join(l3)

def simpleStringReverse(string):
	return string[::-1]

def fireEncode(string):
	string = base64.b64encode(string.encode('utf-16'))
	return string.decode('utf-8')

def fireDecode(string):
	string = base64.b64decode(string)
	return str(string.decode('utf-16'))

# Read file
if not args.I == None:
	debug(">Reading input file..") # Print Debug info
	with open(args.I, "rb") as f:
		inputstring = "".join(map(chr, f.read()))
	debug(">Opened file '%s'" % (args.I)) # Print Debug info
else: inputstring = args.i

# Debug
f1 = inputstring



#Encoding stuffs

def magicEncodingTrick(string, hashcode, mode=True):
	if args.echo:
		run = 0
	if mode:
		hashlist = hashcode
	else:
		hashlist = hashcode[::-1]
	for i in hashlist:
		if args.echo: # Print Debug info
			run+=1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(hashcode)))
			sys.stdout.flush()
		if mode:
			string = replace_all(string, seed_en(i,hashcode)) # Changes characters in the codes using a seed
		else:
			string = replace_all(string, seed_de(i,hashcode)) # unChanges characters in the codes using a seed
	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]\n")
		sys.stdout.flush()
		run = 0
	return string

def mcc_util(n,HASH,mode=True):
	pps = args.salt+HASH
	ps = hashlib.md5(pps.encode())
	s = ps.hexdigest()
	r.seed(s)
	m,d,L = [],{},[]
	for s in range(n):
		for i in l:
			c = r.choice(l)
			while c in m:
				c = r.choice(l)
			m.append(c)
			if mode:
				d[i] = c
			else:
				d[c] = i
		L.append(d)
		m,d = [],{}
	return L

# shiL should be lower than shiH - prime numbers only. (the higher the better)
shiL = 7
shiH = 11
endicnum1,endicnum2 = mcc_util(shiL,psa),mcc_util(shiH,psa)
dedicnum1,dedicnum2 = mcc_util(shiL,psa,False),mcc_util(shiH,psa,False)

# This is slow, but very effective!
def magicCharacterChanger(string, HASH, mode=True):
	if mode:
		mcc = ''.join(endicnum1[i%shiL][c] for i,c in enumerate(string))
		return ''.join(endicnum2[i%shiH][c] for i,c in enumerate(mcc))
	else:
		mcc = ''.join(dedicnum2[i%shiH][c] for i,c in enumerate(string))
		return ''.join(dedicnum1[i%shiL][c] for i,c in enumerate(mcc))
 
def seed_shiftd(n,HASH): # For reversing character change
  pps = args.salt+HASH
  ps = hashlib.md5(pps.encode())
  s = ps.hexdigest()
  r.seed(s)
  m,d,L = [],{},[]
  for s in range(n):
    for i in l:
      c = r.choice(l)
      while c in m:
        c = r.choice(l)
      m.append(c)
      d[c] = i




def moveThingsAround(string, mode=True):
	return magicCharacterChanger(string, psa, mode)

def printdebug(value):
	if value:
		print("DEBUG: PASS")
	else:
		print("DEBUG: FAIL")

if args.e:

	debug(">Converting characters to Unicode bytes..") # Print Debug info
	encodedString = fireEncode(inputstring) # Strint > Encode

	if args.debug: # attemps to backtrack
		print("Debugging 1..")
		backtrack = fireDecode(encodedString)
		printdebug((backtrack == inputstring))
	
	debug(">Adding our special sauce..") # Print Debug info
	sauced1 = moveThingsAround(encodedString) # scram_en() x 2 (each one calls a seeded random.shuffle())
	sauced2 = scram_en(sauced1) # Seeded random.shuffle()

	if args.debug: # attemps to backtrack
		print("Debugging 2..")
		backtrack = scram_de(sauced2)
		backtrack = moveThingsAround(backtrack, False)
		printdebug((backtrack == encodedString))

	debug(">Doing a magic trick.. 1/3") # Print Debug info
	magicString1 = magicEncodingTrick(sauced2, ppw1) # For i in hashcode (ppw1 in this case), change every letter in the source with a generated one with "i" as the seed

	if args.debug: # attemps to backtrack
		print("Debugging 3..")
		backtrack = magicEncodingTrick(magicString1, ppw1, False)
		printdebug((backtrack == sauced2))

	debug(">Moving things around.. 1/2") # Print Debug info
	mixed1 = scram_en(magicString1) # Seeded random.shuffle()

	if args.debug: # attemps to backtrack
		print("Debugging 4..")
		backtrack = scram_de(mixed1)
		printdebug((backtrack == magicString1))

	debug(">Doing a magic trick.. 2/3") # Print Debug info
	magicString2 = magicEncodingTrick(mixed1, psa) # For i in hashcode (psa in this case), change every letter in the source with a generated one with "i" as the seed

	if args.debug: # attemps to backtrack
		print("Debugging 5..")
		backtrack = magicEncodingTrick(magicString2, psa, False)
		printdebug((backtrack == mixed1))

	debug(">Moving things around.. 2/2") # Print Debug info
	backwardsMagic = simpleStringReverse(magicString2) # "Reverses the source" | "ecruos eht sesreveR"
	mixed2 = scram_en(backwardsMagic) # Seeded random.shuffle()

	if args.debug: # attemps to backtrack
		print("Debugging 6..")
		backtrack = scram_de(mixed2) # Seeded random.shuffle()
		backtrack = simpleStringReverse(backtrack) # "Reverses the source" | "ecruos eht sesreveR"
		printdebug((backtrack == magicString2))

	debug(">Doing a magic trick.. 3/3") # Print Debug info
	f1_fin = magicEncodingTrick(mixed2, ppw2) # For i in hashcode (ppw2 in this case), change every letter in the source with a generated one with "i" as the seed

	if args.debug: # attemps to backtrack
		print("Debugging 7..")
		backtrack = magicEncodingTrick(f1_fin, ppw2, False)
		printdebug((backtrack == mixed2))

	debug(">Done with edit.") # Print Debug info

#Decoding stuffs
elif args.d:

	debug(">Checking for bad characters..") # Print Debug info
	splitInput = inputstring.split('\n', 1)[0] # Splits decription input lines to allow comments
	cleanString = ''.join(char if char in l else '' for char in splitInput) # Removed illegal characters. Not that it maters, because such charaters would mean a currupted string.
	
	debug(">Doing a magic trick.. 1/3")
	magicString1 = magicEncodingTrick(cleanString, ppw2, False) # For i in hashcode (ppw2 in this case), change every letter in the source back from the generated one with "i" as the seed

	if args.debug: # attemps to backtrack
		print("Debugging 1..")
		backtrack = magicEncodingTrick(magicString1, ppw2)
		printdebug((backtrack == cleanString))

	debug(">Moving things around.. 1/2")
	mixed1 = scram_de(magicString1) # Seeded reversal of random.shuffle()
	demixified = simpleStringReverse(mixed1) # "Reverses the source" | "ecruos eht sesreveR"

	if args.debug: # attemps to backtrack
		print("Debugging 2..")
		backtrack = simpleStringReverse(demixified)
		backtrack = scram_en(backtrack)
		printdebug((backtrack == magicString1))

	debug(">Doing a magic trick.. 2/3") # Print Debug info
	magicString2 = magicEncodingTrick(demixified, psa, False) # For i in hashcode (psa in this case), change every letter in the source back from the generated one with "i" as the seed

	if args.debug: # attemps to backtrack
		print("Debugging 3..")
		backtrack = magicEncodingTrick(magicString2, psa)
		printdebug((backtrack == demixified))

	debug(">Moving things around.. 2/2")
	mixed2 = scram_de(magicString2) # Seeded reversal of random.shuffle()

	if args.debug: # attemps to backtrack
		print("Debugging 4..")
		backtrack = scram_en(mixed2)
		printdebug((backtrack == magicString2))

	debug(">Doing a magic trick.. 3/3") # Print Debug info
	magicString3 = magicEncodingTrick(mixed2, ppw1, False) # For i in hashcode (ppw1 in this case), change every letter in the source back from the generated one with "i" as the seed

	if args.debug: # attemps to backtrack
		print("Debugging 5..")
		backtrack = magicEncodingTrick(magicString3, ppw1)
		printdebug((backtrack == mixed2))

	debug(">Removing our special sauce..")
	desauced1 = scram_de(magicString3) # Seeded reversal of random.shuffle()
	desauced2 = moveThingsAround(desauced1, False) # scram_de() x 2 (each one calls a seeded reversal of random.shuffle())
	
	if args.debug: # attemps to backtrack
		print("Debugging 6..")
		backtrack = moveThingsAround(desauced2)
		backtrack = scram_en(backtrack)
		printdebug((backtrack == magicString3))

	debug(">Converting Unicode bytes to characters..")
	f1_fin = fireDecode(desauced2)

	if args.debug: # attemps to backtrack
		print("Debugging 7..")
		backtrack = fireEncode(f1_fin)
		printdebug((backtrack == desauced2))

	debug(">Done with edit.")

# Checks output
e = ".cfc"
if args.o == False:
	if not args.O == None:
		o,s = os.path.splitext(args.O)
		outputfile = args.O
		ck = 1
		while os.path.isfile(outputfile) == True:
			outputfile = o+"("+str(ck)+")"+s
			ck = ck + 1
	else:
		if not args.I == None:
			o,s = os.path.splitext(args.I)
			outputfile = o+e
			ck = 1
		else:
			o = "output"
			outputfile = o+e
			ck = 1
		while os.path.isfile(outputfile) == True:
			outputfile = o+"("+str(ck)+")"+e
			ck = ck + 1
	debug(">Saving changes to file..") # Print Debug info
	with open(outputfile, "w") as f:
		f.write(f1_fin)
	debug(">Changes saved to: "+outputfile) # Print Debug info

debug("Processed '%s' characters in '%s' seconds." % (str(len(f1)),str(time.time()-start)))

if args.remove:
	debug(">Deleting input file - Basic shredding") # Print Debug info
	ou = ''
	with open(args.I, 'r+b') as f:
		for i in f.read():
			f.seek(0)
			ou = random.choice(l)+ou+random.choice(l)
			f.write(ou)
		for i in range(15):
			ou = ''
			with open(args.I, 'r+b') as f:
				for i in f.read():
					f.seek(0)
					ou = random.choice(l)+ou
				f.write(ou)

	os.remove(args.I)

if args.o:
	print("[--output--]\n%s\n[--output--]" % (f1_fin))
