### Note: This project is being rebuilt in C# here: https://github.com/TheCyaniteProject/CursePanda
---
## Firecoder - Procedual Data Encryption

Firecoder is a command-line app that uses a combination of procedural cyphers, and (optional) user-configurable encryption sequences, and custom (UTF-8) character ranges that the encryption can encode as.

#### Sequences:

###### (Below is the help print-out from the utility)

    Sequence help. This is a list of all flags and what they do.
    (Non-Sequence Characters will raise an error)

    Sequence example: ?!*/~*/~*!/*  # This is our default sequence, we highly
    recommend you use a custom one.

    ?       Wheither or not to enable Unicode support. Causes a potential
            vulnerability in that incorrect decryption raises an Error
            (makes brute-forcing slightly easier)
            If used, this character must start the Sequence and may only be
            used once.

    !       Triggers our magicCharacterChanger() function which changes each
            character based off of it's position. This is very effective,
            as it doesn't mix characters, but generates dictonaries for them.
            Because of this, this proccess can be very slow, especially with
            long sources.

    *       Triggers our magicEggScrambler() function which simply mixes up all
            existing characters in the source.

    /       Triggers our magicEncodingTrick() function which changes the whole
            source for every character in the HASH.

    ~       Triggers our simpleStringReverse() function which simply reverses
            the source. We recommend using this at least once and as many times
            as you can, as it adds very little overhead.

#### Ranges:

Ranges are simple statements that restrict or expand the available characters that can be used during encryption. An example of a custom range would be something like: "abcd12345-" Though, you could do something much more complex than this.
### 

	Here are the characters in the default range:
	0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&*+,-./:;<=>?@\^_`|~

---
	Here are some range_shortcuts to help you on your way:
	"?a" - abcdefghijklmnopqrstuvwxyz
	"?A" - ABCDEFGHIJKLMNOPQRSTUVWXYZ
	"?d" - 1234567890
	"?s" - "!#$%&*+,-./<=>?@\\^_`|~"
	"?S" - "():;[\"]{'}"


#### Here are a few examples:

##### Basic example
	>> firecoder_main.py -i "This is a test!!" -e -p password!!!
	f&&@43@jE#E/xo>tI~d`M_RJOc!*L$2?~@s1uUVC!iID*U6@

##### Basic example + custom salt (default would be the password backwards)
	>> firecoder_main.py -i "This is a test!!" -e -p password!!! —salt salty!
	eYi<wG@c&JM>T#kQsSCtRRtqAL@,JPHRgnjpn477-*o|EzlS

##### Custom sequence (encryption algo) with Unicode support
	>> firecoder_main.py -i "This is a test!!" -e -p password!!! —seq "?!**/*//*/*!/~/*~/*!"
	Ycu@,3NeE#nQGKm/hSkikc!|mRT8$r@ICE=?a$1H1%j.3L2`

##### Custom sequence (encryption algo) without Unicode support (ASCII)
	>> firecoder_main.py -i "This is a test!!" -e -p password!!! --seq "!**/*//*/*!/~/*~/*!"
	:0p9^,^8>|4?a@&&sYJUKPdTh$dL?il2

##### Custom sequence + custom range of legal characters (No Unicode Support)
	>> firecoder_main.py -i "This is a test!!" -e -p password!!! —seq "!**/*//*/*!/~/*~/*!" —range "abcd12345-"
	dac35254--5-131b-4-ac51ab55b31db

###### I am not paid to work on Firecoder, nor do I have a regular job. If you would like to help support me and Firecoder, please consiter donating:
http://paypal.me/TheCyaniteProject
