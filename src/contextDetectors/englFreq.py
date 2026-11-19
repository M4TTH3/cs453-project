# letter frequency data:
# (I used the first just as a proof of concept, but there is a lot of
#   research in this area)
# https://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
# https://books.google.ca/books?id=CyCcRAm7eQMC&pg=PA36&redir_esc=y#v=onepage&q&f=false
# https://web.archive.org/web/20080708193159/http://pages.central.edu/emp/LintonT/classes/spring01/cryptography/letterfreq.html
# https://homepages.math.uic.edu/~leon/mcs425-s08/handouts/char_freq2.pdf

# average length of english word:
# https://www.norvig.com/mayzner.html

# average nof words per sentence:
# https://lifelong-learning.ox.ac.uk/sentence-length/

# some stuff about numbers:
# https://pmc.ncbi.nlm.nih.gov/articles/PMC10853912/

# NOTE: MORE ANALYSIS NEEDS TO BE DONE, THIS IS JUST A PROOF OF CONCEPT

AVERAGE_LETTERS_PER_WORD = 4.7
AVERAGE_WORDS_PER_SENTENCE = 17.5

letterFrequency = {
    'e': 12.02,
    't': 9.10,
    'a': 8.12,
    'o': 7.68,
    'i': 7.31,
    'n': 6.95,
    's': 6.28,
    'r': 6.02,
    'h': 5.92,
    'd': 4.32,
    'l': 3.98,
    'u': 2.88,
    'c': 2.71,
    'm': 2.61,
    'f': 2.30,
    'y': 2.11,
    'w': 2.09,
    'g': 2.03,
    'p': 1.82,
    'b': 1.49,
    'v': 1.11,
    'k': 0.69,
    'x': 0.17,
    'q': 0.11,
    'j': 0.10,
    'z': 0.07
}

def averageLetterWeight():
    return sum(letterFrequency.values()) / 26

# NOTE: the following three calculations are basically made up
def spaceWeight():
    return averageLetterWeight() / AVERAGE_LETTERS_PER_WORD

def numberWeight():
    return averageLetterWeight() / AVERAGE_WORDS_PER_SENTENCE

def specialWeight():
    return averageLetterWeight() / AVERAGE_WORDS_PER_SENTENCE

def getCharWeight(cbin):
    c = int.from_bytes(cbin, "big")

    # uppercase letters
    if c >= 65 and c <= 90:
        return letterFrequency.get(chr(c).lower())
    
    # lowercase letters
    elif c >= 97 and c <= 122:
        return letterFrequency.get(chr(c))
    
    # space
    elif c == 32: # what about other whitespace?
        return spaceWeight()

    # numbers
    elif c >= 48 and c <= 57:
        return numberWeight()

    # special characters
    elif c >= 33 and c <= 126:
        return specialWeight()
    
    # non-english characters
    else:
        return -1 # should this be even more negative?

def averageCharWeight():
    NOF_LETTERS = 26
    NOF_NUMBERS = 10
    NOF_SPECIAL = 126 - 32 - NOF_LETTERS * 2 - NOF_NUMBERS + 1

    return (averageLetterWeight() * NOF_LETTERS +
            spaceWeight() + 
            numberWeight() * NOF_NUMBERS + 
            specialWeight() * NOF_NUMBERS
            ) / (NOF_LETTERS + 1 + NOF_NUMBERS + NOF_SPECIAL)