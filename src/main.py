#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Cyan's FireCoder - A CYANITE PROJECT

version = "5.1"

# Imports
import re

import os
import re
import sys
import time
import math
import zlib
import base64
import string
import random
import hashlib
import argparse

if not __name__ == "__main__":
    print("Don't import me! Bad!")
    sys.exit(2)

# Variables
r = random.Random()
start = time.time()
errorflag = False
outputEncode = 'utf-8' # List of available codecs: https://docs.python.org/2.4/lib/standard-encodings.html
default_sequence = "?!*/~*/~*!/*"
legal_seq_chars  = "?!*/~[]"
defaultPrime = 17 # A prime number: Larger = more secure, but slower.
exe = ".cfc"
default_letters = (string.digits +
    string.ascii_letters +
    string.punctuation
        .replace('"','')
        .replace("'",'')
        .replace("[",'')
        .replace("]",'')
        .replace("{",'')
        .replace("}",'')
        .replace("(",'')
        .replace(")",'')
        .replace(":",'')
        .replace(";",''))
letterList = [i for i in string.printable]
range_shortcuts = {
    "?a" : string.ascii_lowercase,
    "?A" : string.ascii_uppercase,
    "?d" : string.digits,
    "?s" : "!#$%&*+,-./<=>?@\\^_`|~",
    "?S" : "():;[\"]{'}"
    }
stashList = [] # We pre-define this to make things easier..


default_rangelen = (math.ceil(math.log(len(letterList), len(default_letters))))

seq_help = '''\tSequence help. This is a list of all flags and what they do.
    (Non-Sequence Characters will raise an error)

    Sequence example: %s  # This is our default sequence, we highly
    recommend you use a custom one.

    ?    Wheither or not to enable Unicode support. Causes a potential
        vulnerability in that incorrect decryption raises an Error
        (makes brute-forcing slightly easier)
        If used, this character must start the Sequence and may only be
        used once.

    !    Triggers our magicCharacterChanger() function which changes each
        character based off of it's position. This this is very effective,
        as it doesn't mix characters, but generates dictonaries for them.
        Because of this, this proccess can be very slow, especially with
        long sources.

    *    Triggers our magicEggScrambler() function which simply mixes up all
        existing characters in the source. 

    /    Triggers our magicEncodingTrick() function which changes the whole
        source for every character in the HASH.

    ~    Triggers our simpleStringReverse() function which simply reverses
        the source. We recommend using this at least once and as many times
        as you can, as it adds very little overhead.
''' % default_sequence

def printTitle():
    print("===== Cyan's FireCoder v%s - A Cyanite Project =====\n" % version)

# Command line stuffs
arg = argparse.ArgumentParser(description="Encodes/Decodes messages and files - requires [-I | -i] [-e | -d] [-p PASSWORD]")
conf = arg.add_mutually_exclusive_group()
conf2 = arg.add_mutually_exclusive_group()
conf3 = arg.add_mutually_exclusive_group()
conf.add_argument("-I",  metavar=("FILENAME"), help="specify the file to edit", default=None)
conf.add_argument("-i",  metavar=("MESSAGE"), help="specify the message to edit", default=None)
conf2.add_argument("-e", help="specify use encrypt mode", action="store_true")
conf2.add_argument("-d", help="specify use decrypt mode", action="store_true")
conf3.add_argument("-o", help="prints output to generic file", action="store_true")
conf3.add_argument("-O", metavar=("OUTPUT"), help="sets the output file (default prints output to console)", default=None)
arg.add_argument("-p", metavar=("PASSWORD"), help="specify the password", default=None)
arg.add_argument("--salt", help="add a custom salt (default is the reversed password)", default=False)
arg.add_argument("--seq", metavar=("SEQUENCE"), help="set a custom encryption sequence - pass: '--seqhelp' for more info - default sequence: %s" % default_sequence, default=default_sequence)
arg.add_argument("--range", metavar=("CHARACTERS"), help="set a custom ASCII character range to be used during encription, this range will be sampled repeatedly and will change the resulting output (minumum of 10 characters, utf-8 compatable) - default uses the entire ASCII range, minus: '\"[]{}()", default=default_letters)
arg.add_argument("--rangelen", help="The length of each character after encryption - default length: %s" % default_rangelen, default=default_rangelen)
arg.add_argument("--codec", help="set a custom codec for writing files - list of available codecs: https://docs.python.org/2.4/lib/standard-encodings.html - default codec: %s" % outputEncode, default=None)
arg.add_argument("--seqhelp", help="prints help related to how sequences work, and what each character does, and then exits", action="store_true")
arg.add_argument("--echo", help="prints extra info (including the current password and HASH in plain text)", action="store_true")
arg.add_argument("--debug", help="enables debug mode (this attemps to backtrack the encrption at each step to make sure decryption is possible)", action="store_true")
arg.add_argument("--remove", help="deletes the input file after compleation", action="store_true")
arg.add_argument("-c", "--compress", help="Compresses the encrypted file when saving.", action="store_true")
args = arg.parse_args()



# Title, Help & Exit if no arguments are passed
if len(sys.argv)==1:
    printTitle()
    arg.print_help()
    sys.exit(1)

if args.seqhelp:
    printTitle()
    print(seq_help)
    sys.exit(1)

 
def argumentChecker():
    """Here we check if we are missing anything, check argument compatibility, and do some setup for missing arguments
    
    :Date:: 11/11/2017

    :Author:: Allison Smith
    """

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
    
    # Check file save method
    if not args.codec == None:
        if not args.o and (args.O == None):
            arg.error("can't use [--codec]: not saving to file")
            sys.exit(1) #Exit with minor error
    else:
        args.codec = outputEncode
    
    # Check custom range
    for flag, chars in range_shortcuts.items():
        if flag in args.range:
            args.range = args.range.replace(flag, chars)
    if not int(args.rangelen) >= (math.ceil(math.log(len(letterList), len("".join(set(args.range)))))):
        arg.error("range length must be at least %s" % (math.ceil(math.log(len(letterList), len("".join(set(args.range)))))))
        sys.exit(1) #Exit with minor error
    else:
        flags = []
        for char in args.range:
            if args.range.count(char) > 1:
                if not char in flags:
                    flags.append(char)
        if flags:
            print("One (or more) characters appeared more than once: %s (extra occurrences will be stripped)" % ", ".join(flags))
    args.range = "".join(sorted(set(args.range)))

argumentChecker() # Run the function we just created. We only created it for organazation

if args.debug or args.echo:
    printTitle()

# These messages will be printed if --echo is passed
def debug(string="Default text"):
    """Print string if args.echo(--echo argument)

    :Parameters:: 

        string -- The string to print (default: "Default text")

    :Date:: 11/11/2017
    
    :Author:: Allison Smith
    """

    if args.echo:
        print(string)

# Utilities
def setErrorFlag(flag=True):
    global errorflag
    errorflag = flag

def debugexit():
    """Prints a message, and then calls sys.exit(2)

    For use in debugging

    :Date:: 11/11/2017
    
    :Author:: Allison Smith
    """

    print("[!!DEBUG EXIT!!]")
    sys.exit(2)

def percentage(part, whole): # Used for the loading bars in the debug output
    """Returns a % of a given number.

    :Parameters:: 

        part -- The fraction of the whole number

        whole -- The whole number

    :Date:: Before 11/11/2017 (Legacy Version)
    
    :Author:: Allison Smith
    """

    return 100 * float(part)/float(whole)

# Link START!!! :D

# Debug mode?
if args.debug:
    print(">> Debug ON <<")
debug("Output:")
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

# Modifiers

def replace_all(string, dic, mode=True):
    """Replaces every value (from 'dic') in 'string' for key in 'dic'

    :Parameters:: 

        string -- The string to edit

        dic -- The dictionary to use for the edit

        mode -- True/False is the script running in encoding mode? (default: True)

    :Date:: 11/12/2017

    :Updated:: 11/15/2017
    
    :Author:: Allison Smith
    """

    if not mode:
        string = [string[i:i + int(args.rangelen)] for i in range(0, len(string), int(args.rangelen))]
    return ''.join(str(dic.get(word, word)) for word in string)



def gen_keys(HASH,char='A',mode=True):
    """Generates a dictonary with a key/value for each item in 'args.range' ('args.range' is a string of legal characters)

    This is used to convert each item in a string into another character, and back.

    :Parameters:: 

        char -- A character to combine with the hash (default: 'A')

        HASH -- The hash to use in seeding random.choice()

        mode -- True/False is the script running in encoding mode? (default: True)

    :Date:: 11/12/2017
    
    :Author:: Allison Smith
    """

    r.seed(hashlib.sha1((str(char)+str(HASH)).encode()).hexdigest())
    m,d = [],{}
    for i in args.range:
        c = r.choice(args.range)
        while c in m:
            c = r.choice(args.range)
        m.append(c)
        if mode:
            d[i] = c
        else:
            d[c] = i
    return d

def gen_codes(HASH,char='A',mode=True):
    """Generates a dictonary with a key/value for each item in 'letterList' ('letterList' is a list of legal characters)

    This is different from gen_keys() in that it is used to convert each item in a string into a two-digit code, and back.

    (For use when not handling unicode)

    :Parameters::

        char -- A character to combine with the hash (default: 'A')

        HASH -- The hash to use in seeding random.choice()

        mode -- True/False is the script running in encoding mode? (default: True)

    :Date:: 11/14/2017
    
    :Author:: Allison Smith
    """

    pps = char+HASH
    ps = hashlib.md5(pps.encode())
    s = ps.hexdigest()
    r.seed(s)
    m,d = [],{}
    for i in letterList:
        c = "".join([r.choice(args.range) for i in range(int(args.rangelen))])
        while c in m:
            c = "".join([r.choice(args.range) for i in range(int(args.rangelen))])
        m.append(c)
        if mode:
            d[i] = c
        else:
            d[c] = i
    return d

def magicEggScrambler(string, mode=True):
    """Calls random.shuffle() on the string with 'psa' as the seed.

    Is able to shuffle/unshuffle depending on the mode.

    :Sequence Character:: * (This function's character when calling in a custom sequence)

    :Parameters:: 

        string -- The string to edit

        mode -- True/False is the script running in encoding mode? (default: True)

    :Date:: 11/12/2017
    
    :Author:: Allison Smith
    """

    if mode:
        l = list(string)
        r.seed(hashlib.sha1(psa.encode()).hexdigest())
        r.shuffle(l) # Every day I'm shufflinnnnn~
        return ''.join(l)
    else:
        l = list(string)
        l2 = list(range(len(l)))
        r.seed(hashlib.sha1(psa.encode()).hexdigest())
        r.shuffle(l2)
        l3 = [0]*len(l)
        for index,originalIndex in enumerate(l2):
            l3[originalIndex] = l[index]
        return ''.join(l3)

def simpleStringReverse(string):
    """Simply reverses the imput string.

    :Sequence Character:: ~ (This function's character when calling in a custom sequence)

    :Parameters:: 

        string -- The string to edit

    :Date:: 11/12/2017
    
    :Author:: Allison Smith
    """
    return string[::-1]

def StringStripper(string, mode=True):
    """In encode mode; removes any charaters not found in 'letterList' ('letterList' is a list of legal characters) and replaces them with a '?'.

    In both modes; calls replace_all() with gen_codes() as the dictionary. (This sets/unsets all characters into two digit codes)

    This is used when not handling Unicode.

    :Parameters:: 

        string -- The string to edit

        mode -- True/False is the script running in encoding mode? (default: True)

    :Date:: 11/14/2017
    
    :Author:: Allison Smith
    """

    if args.e:
        string = ''.join(char if char in letterList else '?' for char in string)
    return replace_all(string, gen_codes(psa,"l",mode), mode)


def fireCoderMethod(string, mode=True):
    """A function for handling Unicode.

    This (in encode mode) will encode the input string as UTF-16 bytes, and then as base64. (In decode mode, it's decoded in reverse)

    :Sequence Character:: ? (This function's character when calling in a custom sequence)

    :Parameters:: 

        string -- The string to edit

        mode -- True/False is the script running in encoding mode? (default: True)

    :Date:: 11/11/2017
    
    :Author:: Allison Smith
    """

    if mode:
        return fireEncode(string)
    return fireDecode(string)

def fireEncode(string):
    """A function for handling Unicode.

    This is the encode method.

    :Sequence Character:: ? (This function's character when calling in a custom sequence)

    :Parameters:: 

        string -- The string to edit

    :Date:: 11/11/2017
    
    :Author:: Allison Smith
    """

    string = base64.b64encode(string.encode('utf-16'))
    return string.decode('utf-8')

def fireDecode(string):
    """A function for handling Unicode.

    This is the decode method.

    :Sequence Character:: ? (This function's character when calling in a custom sequence)

    :Parameters:: 

        string -- The string to edit

    :Date:: 11/11/2017
    
    :Author:: Allison Smith
    """

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

    if args.d:
        with open(args.I, 'rb') as inFile: # binary
            if args.compress: # COMPRESSION-TEST
                inputstring = "".join(map(chr, zlib.decompress(inFile.read())))
            else:
                inputstring = inFile.read()
    else:
        try:
            with open(args.I, 'r', encoding='ascii') as inFile: # non-binary
                inputstring = inFile.read()
        except:
            try:
                with open(args.I, 'r', encoding='utf-8-sig') as inFile: # non-binary
                    inputstring = inFile.read()
            except:
                with open(args.I, 'rb') as inFile: # binary
                    inputstring = "".join(map(chr, inFile.read()))
    debug(">Opened file '%s'" % (args.I)) # Print Debug info
else: inputstring = args.i

# Debug
f1 = inputstring



#Encoding stuffs

def magicEncodingTrick(string, HASH, mode=True):
    """For each character (i) in the HASH, gen_keys(HASH,i,mode) and replace_all() in string from that generated dictonary.

    :Sequence Character:: / (This function's character when calling in a custom sequence)

    :Parameters:: 

        string -- The string to edit

        HASH -- The hash to pass to gen_keys()

        mode -- True/False is the script running in encoding mode? (default: True)

    :Date:: 11/14/2017
    
    :Author:: Allison Smith
    """

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
        string = replace_all(string, gen_keys(HASH,i,mode)) # unChanges characters in the codes using a seed
    if args.echo: # Print Debug info
        sys.stdout.write("\r>Working [DONE]\n")
        sys.stdout.flush()
        run = 0
    return string

 
def magicCharacterChanger(string, HASH, prime=5, mode=True):
    """ This generates dictionaries and cuts the source into segments for the length of "prime".
    Once that is done, it uses the dictionaries to change each letter individually. It then does the
    same to the next segment, but also uses the last segment as a seed to re-encode the current segment.

    :Sequence Character:: ! (This function's character when calling in a custom sequence)

    :Parameters:: 

        string -- The string to edit

        mode -- True/False is the script running in encoding mode? (default: True)

    :Date:: 1/7/2018
    
    :Author:: Oliver, from devRant
    """
    listOfDictionaries = []
    output = ''

    try:
        for i in range(prime):
            listOfDictionaries.append(gen_keys(HASH, str(i), mode))
        # Here we cut the input into segments that are the same length as the prime
        stringList = [string[i:i+prime] for i in range(0, len(string), prime)]
        
        if mode:
            for num, segment in enumerate(stringList):

                if not num == 0:
                    segment = replace_all(segment, gen_keys(segment2, 'r', mode))
                segment2 = ''
                for i, char in enumerate(segment):
                    segment2 += replace_all(char, listOfDictionaries[i])
                output += segment2
        else:
            stringList = stringList[::-1]
            for num, segment in enumerate(stringList):
                segment2 = ''

                for i, char in enumerate(segment):
                    segment2 += replace_all(char, listOfDictionaries[i])
                if not num == (len(stringList)-1):
                    segment2 = replace_all(segment2, gen_keys(stringList[num+1], 'r', mode))
                output = segment2 + output
                
                
        return output

    except KeyError as ex:
        print("""Error: Found unknown character in source while enumerating cypher dictionary: %s
This may be a result of loading a .cfc file saved as Unicode. If so, try sanitizing the file and try again.""" % ex)
        sys.exit(2)

def split(s):
    half, rem = divmod(len(s), 2)
    return s[:half + rem], s[half + rem:]
def sourceStasher(source, array, mode=True):
    if mode:
        if len(source) >= 8:
            firstpart, secondpart = split(source)
            array.append(secondpart)
            return firstpart
        else:
            debug("Warn: Source too short to split, skipping.")
            array.append("")
            return source
    output = source+array[len(array)-1]
    array.pop(0)
    return output

def printdebug(value=False):
    """
    
    :Parameters:: 

        value -- An if statement that should return True or false (hopefuly True)
        
	    Example: (value1 == value2)
        
	    Default: False

    :Date:: 11/14/2017
    
    :Author:: Allison Smith
    """

    if value:
        print(">>DEBUG: PASS")
    else:
        print(">>DEBUG: FAIL")

# Main Process

source = inputstring




# Initial pass, check sequence formatting.
for pos, char in enumerate(args.seq):
    if char not in legal_seq_chars:
        print('Error: illegal sequence character: "%s" in position: %i' % (char, pos+1))
        sys.exit(1)


bracketlist = []
for pos, val in enumerate(args.seq):
    if val == "[":
        bracketlist.append(pos)
    elif val == "]":
        if len(bracketlist) == 0:
            print("Error: Misformated bracket(s): ] in position: %s" % (pos+1))
            sys.exit(1)
        else:
            bracketlist.pop()
if len(bracketlist) != 0:
    print("Error: Misformated bracket(s): [ in position: %s" % (bracketlist.pop()+1))
    sys.exit(1)

if "?" in args.seq:
    if args.seq.count("?") > 1:
        print('Error: illegal sequence action: "?" can only be used once')
        sys.exit(1)
    elif not args.seq.startswith("?"):
        print('Error: illegal sequence action: "?" must be the first character of the sequence')
        sys.exit(1)
else:
    if args.e:
        source = StringStripper(source, True)


# Sequence Processing

def backtrackDebugger(title, char, booleanCheck):
    if args.debug:
        print(">>Attempting to backtrack %s(): %i/%i" % (title, args.seq[:pos+1].count(char), args.seq.count(char)))
        printdebug(booleanCheck)

def parseChar(pos, char, mode=True):
    global source
    backtrack = source
    if char == "?":
        source = fireCoderMethod(source, mode)
        backtrackDebugger("fireCoderMethod", '?', (backtrack == fireCoderMethod(source, (not mode))))
    elif char == "!":
        source = magicCharacterChanger(source, str(pos)+ppw1, defaultPrime, mode)
        #backtrackDebugger('magicCharacterChanger', '!', (backtrack == magicCharacterChanger(source, (not mode))))
    elif char == "*":
        source = magicEggScrambler(source, mode)
        backtrackDebugger('magicEggScrambler', '*', (backtrack == magicEggScrambler(source, (not mode))))
    elif char == "/":
        source = magicEncodingTrick(source, str(pos)+ppw2, mode)
        backtrackDebugger('magicEncodingTrick', '/', (backtrack == magicEncodingTrick(source, str(pos)+ppw2, (not mode))))
    elif char == "~":
        source = simpleStringReverse(source)
        backtrackDebugger('simpleStringReverse', '~', (backtrack == simpleStringReverse(source)))
    elif char == "[":
        source = sourceStasher(source, stashList, mode)
    elif char == "]":
        source = sourceStasher(source, stashList, (not mode))

if args.e:
    for pos, char in enumerate(args.seq):
        parseChar(pos, char, True)
elif args.d:
    for pos, char in [(n, args.seq[n]) for n in reversed(range(len(args.seq)))]:
        parseChar(pos, char, False)    
else:
    print('Error: critical unknown error while parsing sequence: "%s" please file an issue!! https://github.com/TheCyaniteProject/firecoder/issues' % args.seq)

if args.d:
    if not "?" in args.seq:
        source = StringStripper(source, False)

debug(">Done with edit.")

if args.debug or args.echo:
    if args.e:
        print("Processed '%i' characters in '%s' seconds." % (len(f1),str(time.time()-start)))
    else:
        print("Processed '%i' characters in '%s' seconds." % (len(source),str(time.time()-start)))

if errorflag:
    if args.e:
        print('Warning! Errors detected! The source may not have been encoded correctly!')
    if args.d:
        print('Warning! Errors detected! The source may not have been decoded correctly!')

def finishingTouches(outputfile="output.cfc"): # For writing files:
    global source
    debug(">Saving to file..") # Print Debug info
    try:
        source = source.encode(args.codec).decode('unicode-escape').encode(args.codec)
        altmode = False
    except (OverflowError, UnicodeDecodeError, UnicodeEncodeError):
        try:
            source = source.encode(args.codec)
            altmode = False
        except Exception as ex:
            try:
                source = source.encode("ascii")
                altmode = True
            except:
                print("""Error: minor encoding error while encoding file: %s
If this problem persists, please file an issue: https://github.com/TheCyaniteProject/firecoder/issues""" % str(ex))
                print("File was not saved.")
            sys.exit(2)
    if altmode:
        with open(outputfile, 'w', encoding=args.codec) as outFile:
            outFile.write(source)
            debug(">Changes saved to: %s | w/ w" % outputfile) # Print Debug info
    else:
        with open(outputfile, 'wb') as outFile:
            if args.e:
                if args.compress: # COMPRESSION-TEST
                    outFile.write(zlib.compress(source))
                else:
                    outFile.write(source)
            else:
                outFile.write(bytes(source))
            debug(">Changes saved to: %s | w/ wb" % outputfile) # Print Debug info

    if args.remove:
        debug(">Deleting input file - Basic shredding") # Print Debug info
        ou = ''
        with open(args.I, 'r+b') as f:
            for i in f.read():
                f.seek(0)
                ou = random.choice(args.range)+ou+random.choice(args.range)
                f.write(ou)
            for i in range(15):
                ou = ''
                with open(args.I, 'r+b') as f:
                    for i in f.read():
                        f.seek(0)
                        ou = random.choice(args.range)+ou
                    f.write(ou)
        os.remove(args.I)

# Checks output
if not args.o:
    if args.O == None:
        if args.echo or args.debug:
            print("\n[--output--]")
        print(source)
    else:
        o,s = os.path.splitext(args.O)
        outputfile = args.O
        ck = 1
        while os.path.isfile(outputfile):
            outputfile = o+"("+str(ck)+")"+s
            ck = ck + 1
        finishingTouches(outputfile)
else:
    if not args.I == None:
        o,s = os.path.splitext(args.I)
        outputfile = o+exe
        ck = 1
    else:
        o = "output"
        outputfile = o+exe
        ck = 1
    while os.path.isfile(outputfile):
        outputfile = o+"("+str(ck)+")"+exe
        ck = ck + 1
    finishingTouches(outputfile)

