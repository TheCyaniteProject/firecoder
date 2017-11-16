#!/usr/bin/python
# -*- coding: utf-8 -*-
# Cyan's FireCoder - A CYANITE PROJECT

version = "4.1"

default_sequence = "?!*/~*/~*!/*"
legal_seq_chars  = "?!*/~"

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
start = time.time()
errorflag = False

seq_help = '''	Sequence help. This is a list of all flags and what they do.
	(Non-Sequence Characters will raise an error)

	Sequence example: %s  # This is our default sequence, we highly
	recommend you use a custom one.

	?	Wheither or not to enable Unicode support. Causes a potential
		vulnerability in that incorrect decryption raises an Error
		(makes brute-forcing slightly easier)
		If used, this character must start the Sequence and may only be
		used once.

	!	Triggers our magicCharacterChanger() function which changes each
		character based off of it's position. This this is very effective,
		as it doesn't mix characters, but generates dictonaries for them.
		Because of this, this proccess can be very slow, especially with
		long sources.

	*	Triggers our magicEggScrambler() function which simply mixes up all
		existing characters in the source. 

	/	Triggers our magicEncodingTrick() function which changes the whole
		source for every character in the HASH.

	~	Triggers our simpleStringReverse() function which simply reverses
		the source. We recommend using this at least once and as many times
		as you can, as it adds very little overhead.
''' % default_sequence


# Command line stuffs
arg = argparse.ArgumentParser(description="Encodes/Decodes messages and files - requires [-I | -i] [-e | -d] [-p PASSWORD]")
conf = arg.add_mutually_exclusive_group()
conf2 = arg.add_mutually_exclusive_group()
conf3 = arg.add_mutually_exclusive_group()
conf.add_argument("-I",  metavar=("FILENAME"), help="specify the file to encrypt", default=None)
conf.add_argument("-i",  metavar=("MESSAGE"), help="specify the message to encrypt", default=None)
conf2.add_argument("-e", help="specify use encode mode", action="store_true")
conf2.add_argument("-d", help="specify use decode mode", action="store_true")
conf3.add_argument("-o", help="prints output to console", action="store_true")
conf3.add_argument("-O", metavar=("OUTPUT"), help="sets the output file", default=None)
arg.add_argument("-p", metavar=("PASSWORD"), help="specify the password for the encryption", default=None)
arg.add_argument("--salt", help="add a custom salt to encryption - this will be used in places other than hashing", default=False)
arg.add_argument("--seq", metavar=("SEQUENCE"), help="set a custom encryption sequence - pass: '--seqhelp' for more info - default sequence: %s" % default_sequence, default=default_sequence)
arg.add_argument("--seqhelp", help="prints help related to how sequences work, and what each character does, and then exits", action="store_true")
arg.add_argument("--echo", help="prints extra info including the current password and HASH in plain text", action="store_true")
arg.add_argument("--debug", help="enables debug mode: this attemps to backtrack the encrption at each step to make sure decryption is possible", action="store_true")
arg.add_argument("--remove", help="deletes the input file after compleation", action="store_true")
args = arg.parse_args()

# Title, Help & Exit if no arguments are passed
if len(sys.argv)==1:
	print("===== Cyan's FireCoder v%s - A Cyanite Project =====\n" % version)
	arg.print_help()
	sys.exit(1)

if args.seqhelp:
	print("===== Cyan's FireCoder v%s - A Cyanite Project =====\n" % version)
	print(seq_help)
	sys.exit(1)


# Here we check if we are missing anything, check argument compatibility, and do some setup for missing arguments
def argumentChecker():

	# Check Password
	if args.p == None:
		arg.error("no password provided [-p PASSWORD]")
		sys.exit(1) #Exit with minor error

	# Sets Salt to reverse-Password if empty.
	if not args.salt:
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
def setErrorFlag(flag=True):
	global errorflag
	errorflag = flag

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
l2 = [i for i in string.printable]

debug(">Done.") # Print Debug info


# Modifiers

def replace_all(string, dic, mode=True):
	if not mode:
		string = [string[i:i + 2] for i in range(0, len(string), 2)]
	return ''.join(str(dic.get(word, word)) for word in string)



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

def gen_codes(char,HASH,mode=True): # For turing the codes back into the original entry
	pps = char+HASH
	ps = hashlib.md5(pps.encode())
	s = ps.hexdigest()
	r.seed(s)
	m,d = [],{}
	for i in l2:
		c = r.choice(l)+r.choice(l)
		while c in m:
			c = r.choice(l)+r.choice(l)
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

def magicEggScrambler(string, mode=True): # sequence character: *
	if mode:
		return scram_en(string)
	return scram_de(string)

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

def simpleStringReverse(string): # sequence character: ~
	return string[::-1]

def StringStripper(string, mode=True):
	if args.e:
		string = ''.join(char if char in l2 else '?' for char in string) # Replaces all unknown characters with: ?
	return replace_all(string, gen_codes("l", psa, mode), mode)


def fireCoderMethod(string, mode=True): # sequence character: ?
	if mode:
		return fireEncode(string)
	return fireDecode(string)

def fireEncode(string):
	string = base64.b64encode(string.encode('utf-16'))
	return string.decode('utf-8')

def fireDecode(string):
	try:
		string = base64.b64decode(string)
		string = str(string.decode('utf-16'))
	except:
		print('''Error: could not decode source as base64. Please check your Password, Salt, and Sequence, and try again.
If this problem persists, please file an issue: https://github.com/TheCyaniteProject/firecoder/issues''')
		#sys.exit(2) # Exit with major error
		setErrorFlag(True)
	return string

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

def magicEncodingTrick(string, HASH, mode=True): # sequence character: /
	if args.echo:
		run = 0
	if mode:
		hashlist = HASH
	else:
		hashlist = HASH[::-1]
	for i in hashlist:
		if args.echo: # Print Debug info
			run+=1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(HASH)))
			sys.stdout.flush()
		if mode:
			string = replace_all(string, seed_en(i,HASH)) # Changes characters in the codes using a seed
		else:
			string = replace_all(string, seed_de(i,HASH)) # unChanges characters in the codes using a seed
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
def magicCharacterChanger(string, HASH, mode=True): # sequence character: !
	if mode:
		mcc = ''.join(endicnum1[i%shiL][c] for i,c in enumerate(string))
		return ''.join(endicnum2[i%shiH][c] for i,c in enumerate(mcc))
	else:
		mcc = ''.join(dedicnum2[i%shiH][c] for i,c in enumerate(string))
		return ''.join(dedicnum1[i%shiL][c] for i,c in enumerate(mcc))


def moveThingsAround(string, mode=True): # sequence character: !
	return magicCharacterChanger(string, psa, mode)

def printdebug(value):
	if value:
		print("DEBUG: PASS")
	else:
		print("DEBUG: FAIL")

# Main Process

source = inputstring


# Initial pass, check formatting.
pos = 1
for char in args.seq:
	if char not in legal_seq_chars:
		print('Error: illegal sequence character: "%s" in position: %i' % (char, pos))
		sys.exit(2)
	pos += 1
if "?" in args.seq:
	if args.seq.count("?") > 1:
		print('Error: illegal sequence action: "?" can only be used once')
		sys.exit(2)
	elif not args.seq.startswith("?"):
		print('Error: illegal sequence action: "?" must be the first character of the sequence')
		sys.exit(2)
else:
	if args.e:
		source = StringStripper(source, True)

# start with: inputstring

# Sequence Processing

if args.d:
	args.seq = simpleStringReverse(args.seq)

pos = 1
if args.d:
	pos = len(args.seq)
for char in args.seq:
	if args.e:
		if char == "?":
			source = fireCoderMethod(source, True)
		elif char == "!":
			source = magicCharacterChanger(source, ppw1+str(pos), True)
		elif char == "*":
			source = magicEggScrambler(source, True)
		elif char == "/":
			source = magicEncodingTrick(source, str(pos)+ppw2, True)
		elif char == "~":
			source = simpleStringReverse(source)
		pos += 1
	elif args.d:
		if char == "?":
			source = fireCoderMethod(source, False)
		elif char == "!":
			source = magicCharacterChanger(source, ppw1+str(pos), False)
		elif char == "*":
			source = magicEggScrambler(source, False)
		elif char == "/":
			source = magicEncodingTrick(source, str(pos)+ppw2, False)
		elif char == "~":
			source = simpleStringReverse(source)
		pos -= 1
	else:
		print('Error: critical unknown error while parsing sequence: "%s" please file an issue!! https://github.com/TheCyaniteProject/firecoder/issues' % args.seq)

if args.d:
	if not "?" in args.seq:
		source = StringStripper(source, False)

debug(">Done with edit.")

if errorflag:
	if args.e:
		print('Warning! Errors detected! The source may not have been encoded correctly!')
	if args.d:
		print('Warning! Errors detected! The source may not have been decoded correctly!')

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
		f.write(source)
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
	print("[--output--]\n%s\n[--output--]" % (source))
