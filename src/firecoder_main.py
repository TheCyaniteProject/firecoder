#!/usr/bin/python
# -*- coding: utf-8 -*-
# Cyan's FireCoder - A CYANITE PROJECT

version = "3.0.0"

# Imports
import os
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
arg.add_argument("--echo", help="echos debug info including the current password and HASH in plain text", action="store_true")
arg.add_argument("-p", metavar=("PASSWORD"), help="specify the password for the encryption", default=None)
args = arg.parse_args()

# Title, Help & Exit if no arguments are passed
if len(sys.argv)==1:
	print("===== Cyan's FireCoder v%s =====\n" % version)
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

def debugexit():
	print("[!!DEBUG EXIT!!]")
	sys.exit(2)

# Link START!!! :D
print("\n===== Cyan's FireCoder v%s =====\n" % version) # Title echo

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
l = string.digits+string.ascii_letters+string.punctuation.replace('"','').replace("'",'').replace("[",'').replace("]",'').replace("{",'').replace("}",'').replace("(",'').replace(")",'')
l2 = [i for i in string.printable]

debug(">Done.") # Print Debug info

def replace_all(n,t,d):
		if n == 0:
			t = ''.join(d[s] if s in d else s for s in t)
		elif n == 1:
			t=[t[i:i+2] for i in range(0, len(t), 2)]
			t = ''.join(d[s] if s in d else s for s in t)
		else:
			sys.exit(2) # Exit with major error
		return t

def seed_en2(char,HASH): # For swopping around the codes
	r.seed(hashlib.sha1((char+HASH).encode()).hexdigest())
	m,d = [],{}
	for i in l:
		c = r.choice(l)
		while c in m:
			c = r.choice(l)
		m.append(c)
		d[i] = c
	return d

def seed_de2(char,HASH): # For swopping back around the codes
	r.seed(hashlib.sha1((char+HASH).encode()).hexdigest())
	m,d = [],{}
	for i in l:
		c = r.choice(l)
		while c in m:
			c = r.choice(l)
		m.append(c)
		d[c] = i
	return d

def scram_en(msg):
		l = list(msg)
		r.seed(hashlib.sha1(psa.encode()).hexdigest())
		r.shuffle(l)
		return ''.join(l)


def scram_de(msg):
	l = list(msg)
	l2 = list(range(len(l)))
	r.seed(hashlib.sha1(psa.encode()).hexdigest())
	r.shuffle(l2)
	l3 = [0]*len(l)
	for index,originalIndex in enumerate(l2):
		l3[originalIndex] = l[index]
	return ''.join(l3)

def percentage(part, whole): # Used for the loading bars in the debug output
	return 100 * float(part)/float(whole)



if not args.I == None:
	debug(">Reading input file..") # Print Debug info
	with open(args.I, "rb") as f:
		f1 = "".join(map(chr, f.read()))
	debug(">Opened file '%s'" % (args.I)) # Print Debug info
else: f1 = args.i

#Encoding stuffs
if args.e:
	
	debug(">Converting characters to Unicode bytes..") # Print Debug info
	f2 = base64.b64encode(f1.encode('utf-16')) # marker
	f2 = f2.decode('utf-8')

	debug(">Adding our special sauce..")
	f3 = scram_en(f2)
	f3 = scram_en(f3)
	f3 = scram_en(f3)
	if args.echo:
		run = 0
		debug(">Doing a magic trick.. 1/3")
	for i in ppw1:
		if args.echo: # Print Debug info
			run+=1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(ppw1)))
			sys.stdout.flush()
		f4 = replace_all(0,f3, seed_en2(i,ppw1)) # Changes characters in the codes using a seed
	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]")
		sys.stdout.flush()
		run = 0
		debug("\n>Moving things around.. 1/2")
	f5 = f4
	f5 = scram_en(f5)
	debug(">Doing a magic trick.. 2/3") # Print Debug info
	for i in psa:
		if args.echo: # Print Debug info
			run+=1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(psa)))
			sys.stdout.flush()
		f6 = replace_all(0,f5, seed_en2(i,psa)) # Changes characters in the codes using a seed
	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]")
		sys.stdout.flush()
		run = 0
		debug("\n>Moving things around.. 2/2")
	f7 = f6[::-1]
	f8 = f7
	f8 = scram_en(f8)
	debug(">Doing a magic trick.. 3/3") # Print Debug info
	for i in ppw2:
		if args.echo: # Print Debug info
			run+=1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(ppw2)))
			sys.stdout.flush()
		f1_fin = replace_all(0,f8, seed_en2(i,ppw2)) # Changes characters in the codes using a seed
	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]")
		sys.stdout.flush()
		run = 0
		debug("\n>Done with edit.")

#Decoding stuffs
if args.d:
	debug(">Checking for bad characters..") # Print Debug info
	f1 = f1.split('\n', 1)[0] # Splits decription input lines to allow comments
	f2 = ''.join(char if char in l else '' for char in f1)
	if args.echo: # Print Debug info
		run = 0
		debug(">Doing a magic trick.. 1/3")
	for i in ppw2:
		if args.echo: # Print Debug info
			run+=1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(ppw2)))
			sys.stdout.flush()
		f3 = replace_all(0,f2, seed_de2(i,ppw2)) # unChanges characters in the codes using a seed
	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]")
		sys.stdout.flush()
		run = 0
		debug("\n>Moving things around.. 1/2")
	f3 = scram_de(f3)
	f4 = f3
	f5 = f4[::-1]
	debug(">Doing a magic trick.. 2/3") # Print Debug info
	for i in psa:
		if args.echo: # Print Debug info
			run+=1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(psa)))
			sys.stdout.flush()
		f6 = replace_all(0,f5, seed_de2(i,psa)) # unChanges characters in the codes using a seed
	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]")
		sys.stdout.flush()
		run = 0
		debug("\n>Moving things around.. 2/2")
	f6 = scram_de(f6)
	f7 = f6
	debug(">Doing a magic trick.. 3/3") # Print Debug info
	for i in ppw1:
		if args.echo: # Print Debug info
			run+=1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(ppw1)))
			sys.stdout.flush()
		f8 = replace_all(0,f7, seed_de2(i,ppw1)) # unChanges characters in the codes using a seed

	debug("\nRemoving our special sauce..")
	f8 = scram_de(f8)
	f8 = scram_de(f8)
	f8 = scram_de(f8)

	debug("Converting Unicode bytes to characters..")
	f9 = base64.b64decode(f8)
	f10 = str(f9.decode('utf-16'))
	f1_fin = f10

	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]")
		sys.stdout.flush()
		run = 0
		debug("\n>Done with edit.") # marker

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

if not args.o == False:
	print("[--output--]\n%s\n[--output--]" % (f1_fin))
