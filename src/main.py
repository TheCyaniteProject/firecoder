# Cyan's FireCoder v1.0.2

import sys,os,argparse,random,hashlib,time
r = random.Random()
start = time.time()

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
#arg.add_argument("inputfile",  metavar=("FILENAME"), help="Specify the file name for use")
arg.add_argument("-p", metavar=("PASSWORD"), help="specify the password for the file", default=None)
args = arg.parse_args()

if args.salt == False:
        args.salt = args.p[::-1]

# Check if input was provided
if args.i == None:
	if args.I == None:
		arg.error("no input selected [-I | -i]")
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
		arg.error("no mode provided")
		sys.exit(1) #Exit with minor error

# Check password
if args.p == None:
	arg.error("no password provided")
	sys.exit(1) #Exit with minor error

print "\nCyan's FireCoder v1.0.0\n" # Title echo

if args.echo: # Print Debug info
	print ">> Debug ON <<\nOutput:"
	if not args.e:
		print ">Mode: Decode"
	else:
		print ">Mode: Encode"

# Password Hashing - Its Overkill, i know.
prepw1 = hashlib.md5(args.salt.encode())
ppw1 = prepw1.hexdigest()
pprepw2 = args.salt[::-1]
prepw2 = hashlib.md5(pprepw2.encode())
ppw2 = prepw2.hexdigest()
pw = ppw1[::-1]+args.p+ppw2
ps0 = hashlib.sha1(pw.encode())
psa = ps0.hexdigest()

#Password echo
if args.echo: # Print Debug info
	print ">Password: "+args.p+"\n>Salt: "+args.salt+"\n>HASH: "+psa

#print "Debug exit"
#exit() # Debug exit! Comment out before running!

#Splitting filename for editing - will improve later
if not args.I == None:
	fnm,fend = os.path.splitext(args.I)

# This is for the dictionary generators
if args.echo: # Print Debug info
	print ">Loading generation variables.."
l2 = [" ","0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","\t","\n","~","`","!","@","#","$","%","^","&","*","(",")","_","+","|","-","=","\\","{","}","[","]",":",'"',";","'","<",">","?",",",".","/"]
l = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
l3 = l+' ~`!@#$%^&*()_+|-=\{}[]:";<>?,./'+"'\n\t"
if args.echo: # Print Debug info
	print ">Done."

def replace_all(n,t,d): # For replacing characters in the string with others
	if n == 0:
		r = ''
		for i in t:
			if i in d:
				r+=d[i]
	elif n == 1:
		r,v = '',0
		n = (50 * len(t)) / 100.0
		for i in range(int(n)):
			v+=2
			if t[v-2:v] in d:
				r+=d[t[v-2:v]]
	else:
		sys.exit(2) # Exit with major error
	return r

def seed_shifte(n,HASH): # For changing characters using their position
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
			d[i] = c
		L.append(d)
		m,d = [],{}
	return L

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
		L.append(d)
		m,d = [],{}
	return L

def seed_en1(char,HASH): # For turning the entry into two digit codes
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
		d[i] = c
	return d

def seed_en2(char,HASH): # For swopping around the codes
	pps = char+HASH
	ps = hashlib.md5(pps.encode())
	s = ps.hexdigest()
	r.seed(s)
	m,d = [],{}
	for i in l:
		c = r.choice(l)
		while c in m:
			c = r.choice(l)
		m.append(c)
		d[i] = c
	return d

def seed_de1(char,HASH): # For turing the codes back into the original entry
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
		d[c] = i
	return d

def seed_de2(char,HASH): # For swopping back around the codes
	pps = char+HASH
	ps = hashlib.md5(pps.encode())
	s = ps.hexdigest()
	r.seed(s)
	m,d = [],{}
	for i in l:
		c = r.choice(l)
		while c in m:
			c = r.choice(l)
		m.append(c)
		d[c] = i
	return d

def percentage(part, whole): # Used for the loading bars in the debug output
	return 100 * float(part)/float(whole)
if args.echo: # Print Debug info
	print ">Creating Shifts.."
endicnum1 = seed_shifte(11,psa)
endicnum2 = seed_shifte(15,psa)
dedicnum1 = seed_shiftd(11,psa)
dedicnum2 = seed_shiftd(15,psa)
if args.echo: # Print Debug info
	print ">Done."

if not args.I == None:
	if args.echo: # Print Debug info
		print ">Reading input file.."
	f = open(args.I, "r")
	f1 = f.read()
	f.close()
	if args.echo: # Print Debug info
		print ">Opened file '"+args.I+"'"
		run = 0
else:
	f1 = args.i

#Encoding stuffs
if args.e:
	if args.echo: # Print Debug info
		print ">Checking for unknown characters.."
	f2 = ''.join(char if char in l3 else '?' for char in f1) # Replaces all unknown characters with: ?
	if args.echo: # Print Debug info
		print ">Converting characters into codes.."
	f3 = replace_all(0,f2, seed_en1(psa,psa)) # Changes characters in the document to codes using a seed
	if args.echo: # Print Debug info
		print ">Doing a magic trick.. 1/3"
		run = 0
	for i in ppw1:
		if args.echo: # Print Debug info
			run = run+1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(ppw1)))
			sys.stdout.flush()
		f4 = replace_all(0,f3, seed_en2(i,ppw1)) # Changes characters in the codes using a seed
	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]")
		sys.stdout.flush()
		run = 0
		print "\n>Moving things around.. 1/2"
	f5 = ''.join(endicnum1[i%11][c] for i,c in enumerate(f4)) # Shifts the characters in the document based off of position
	if args.echo: # Print Debug info
		print ">Doing a magic trick.. 2/3"
	for i in psa:
		if args.echo: # Print Debug info
			run = run+1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(psa)))
			sys.stdout.flush()
		f6 = replace_all(0,f5, seed_en2(i,psa)) # Changes characters in the codes using a seed
	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]")
		sys.stdout.flush()
		run = 0
		print "\n>Moving things around.. 2/2"
	f7 = f6[::-1]
	f8 = ''.join(endicnum2[i%15][c] for i,c in enumerate(f7)) # Shifts the characters in the document based off of position
	if args.echo: # Print Debug info
		print ">Doing a magic trick.. 3/3"
	for i in ppw2:
		if args.echo: # Print Debug info
			run = run+1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(ppw2)))
			sys.stdout.flush()
		f1_fin = replace_all(0,f8, seed_en2(i,ppw2)) # Changes characters in the codes using a seed
	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]")
		sys.stdout.flush()
		run = 0
		print "\n>Done with edit."

#Decoding stuffs
if args.d:
	if args.echo: # Print Debug info
		print ">Checking for bad characters.."
	f2 = ''.join(char if char in l else '' for char in f1)
	if args.echo: # Print Debug info
		print ">Doing a magic trick.. 1/3"
		run = 0
	for i in ppw2:
		if args.echo: # Print Debug info
			run = run+1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(ppw2)))
			sys.stdout.flush()
		f3 = replace_all(0,f2, seed_de2(i,ppw2)) # unChanges characters in the codes using a seed
	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]")
		sys.stdout.flush()
		run = 0
		print "\n>Moving things around.. 1/2"
	f4 = ''.join(dedicnum2[i%15][c] for i,c in enumerate(f3)) # unShifts the characters in the document based off of position
	f5 = f4[::-1]
	if args.echo: # Print Debug info
		print ">Doing a magic trick.. 2/3"
	for i in psa:
		if args.echo: # Print Debug info
			run = run+1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(psa)))
			sys.stdout.flush()
		f6 = replace_all(0,f5, seed_de2(i,psa)) # unChanges characters in the codes using a seed
	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]")
		sys.stdout.flush()
		run = 0
		print "\n>Moving things around.. 2/2"
	f7 = ''.join(dedicnum1[i%11][c] for i,c in enumerate(f6)) # unShifts the characters in the document based off of position
	if args.echo: # Print Debug info
		print ">Doing a magic trick.. 3/3"
	for i in ppw1:
		if args.echo: # Print Debug info
			run = run+1
			sys.stdout.write("\r>Working [%d%%]" % percentage(run,len(ppw1)))
			sys.stdout.flush()
		f8 = replace_all(0,f7, seed_de2(i,ppw1)) # unChanges characters in the codes using a seed
	f1_fin = replace_all(1,f8, seed_de1(psa,psa)) # Changes characters from the codes for the document #rev
	if args.echo: # Print Debug info
		sys.stdout.write("\r>Working [DONE]")
		sys.stdout.flush()
		run = 0
		print "\n>Done with edit."

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
	if args.echo: # Print Debug info
		print ">Saving changes to file.."
	f = open(outputfile, "w")
	f.write(f1_fin)
	f.close()
	if args.echo: # Print Debug info
		print ">Changes saved to: "+outputfile

print "Processed '"+str(len(f1))+"' characters in '"+str(time.time()-start)+"' seconds."

if args.remove:
	if args.echo: # Print Debug info
		print ">Deleting input file"
	os.remove(args.I)

if not args.o == False:
	print "[--output--]-----\n"+f1_fin+"\n[--output--]-----"
