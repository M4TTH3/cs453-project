'''
Most current entropy analysis techniques assume nothing about the 
    file type or context, for the sake of generality
However, many of the human-created files that are seen as valuable
    to ransomware attackers (eg. files with text) do have patterns,
    which means there is a disconnect between analysis methods from
    practice
Is it possible to curate specific entropy analysis methods for
    every commonly-used file type, that are efficient enough to
    be run along with existing tools to bolster accuracy?
This would probably require fairly extensive research into human
    patterns and file types, but it may still be valuable to focus
    on a small subset
Minor accuracy improvements to file types that already have robust
    entropy detection methods are still valuable, so long as the
    efficiency is not hampered

One easy example to implement is English language detection for
    files that feature it (txt, MS docs)
Can use a language dictionary to determine which words are common,
    or more simply analyze how common characters are, which is what
    this program does

PDF Documentation:
https://opensource.adobe.com/dc-acrobat-sdk-docs/standards/pdfstandards/pdf/PDF32000_2008.pdf

Zip Documentation:
https://www.loc.gov/preservation/digital/formats/fdd/fdd000354.shtml
https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT

Aside: AI could be used to detect patterns in tricky file formats
If there exists a quick benchmark to identify possible problems,
    only a select few suspicious files need to be sent to
    extensive analysis
In theory, file compression should have noticeably less entropy
    than encryption since legibility is not a concern, nothing
    like a key is needed to unzip, and compression already relies
    on patterns and a well-defined format

'''
    
import io
from englFreq import getCharWeight
from englFreq import averageCharWeight

# TODO: 
# Convert into proper detector format
# Include more contexts and tune their tests

def fileTypeDetector():

    filePath = "sample.zip"
    f = open(filePath, "rb")

    '''
    The general idea is to assign a weight to each English character
        where rarer characters are lighter, compare the file's total
        weight to the expected/average weight given its length
    Weights for special characters and numbers were assigned
        somewhat arbitrarily, nor was capitalization considered
    These could be accounted for fairly easily
    '''

    weight = 0
    length = 0
    while True:
        c = f.read(1)
        if int.from_bytes(c, "big") == 0:
            break
        length += 1
        weight += getCharWeight(c)

    ACCEPTABLE_THRESHOLD = 0.25
    if weight / (length * averageCharWeight()) < 1 - ACCEPTABLE_THRESHOLD:
        print("This file does not seem to be English text") # raise some actual error
    else:
        print("This file seems like English")

    # print(length * averageCharWeight())
    # print(weight)

    f.close()