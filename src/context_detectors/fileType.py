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
    
import asyncio
import os
import time
from typing import ClassVar
from pathlib import Path

from simulation import Detector, Log, Result
from syscall import Op, SysCall, TraceEvent

from .englFreq import getCharWeight
from .englFreq import averageCharWeight

# TODO: Include more contexts and tune all tests

# create base class for all context detectors
#   and a director that tracks which files fit which contexts?
class EnglTxtDetector(Detector):
    """
    Detects whether a plaintext file is in English.
    Should be configured to only watch files known to match the language,
    possibly by scanning all files during initialization.
    """

    "Weight ratio deemed concerning"
    threshold: float

    MUTATING_OPS: ClassVar[frozenset[Op]] = frozenset({Op.WRITE, Op.TRUNCATE, Op.UNLINK, Op.RENAME})

    "Known English plaintext files"
    englTxts: set[str]
    hit: asyncio.Future[TraceEvent]

    def __init__(self, threshold: float = 0.25) -> None:
        self.threshold = threshold

    def setup(self, syscall: SysCall, safe_path: Path, log: Log) -> None:
        self.hit = asyncio.get_running_loop().create_future()
        self.englTxts = set()

        # TODO: scan directory for plaintext English files and watch only them
        # self._englLangInit(safe_path)

        watched = ", ".join(sorted(self.MUTATING_OPS))
        log(f"threshold={self.threshold}, watching {watched}")

    def on_event(self, event: TraceEvent) -> None:
        # if event.op in self.MUTATING_OPS and event.path in self.englTxts and not self.hit.done():
        if event.op in self.MUTATING_OPS and not self.hit.done():
            if type(event.path) == str and self._englLangTest(event.path):
                self.hit.set_result(event)

    async def start(self, syscall: SysCall, safe_path: Path, log: Log) -> Result:
            start = time.perf_counter()
            event = await self.hit

            return Result(
                detected=True,
                duration=time.perf_counter() - start,
                message=f"Plaintext English file {event.path} has been suspiciously modified by {event.op}",
            )

    def _englLangTest(self, path: str) -> bool:
        '''
        The general idea is to assign a weight to each English character
            where rarer characters are lighter, compare the file's total
            weight to the expected/average weight given its length
        Weights for special characters and numbers were assigned
            somewhat arbitrarily, nor was capitalization considered
        These could be accounted for fairly easily
        '''

        # filePath = "sample.zip"
        f = open(path, "rb")

        weight = 0
        length = 0
        while True:
            c = f.read(1)
            if int.from_bytes(c, "big") == 0:
                break
            length += 1
            weight += getCharWeight(c)

        isEnglTxt = True
        if length == 0 or weight / (length * averageCharWeight()) < 1 - self.threshold:
            isEnglTxt = False

        f.close()

        return not(isEnglTxt)

    def _englLangInit(self, dir: Path) -> None:
        # for entry in os.scandir(dir):  
        #     if entry.is_file():
        #         print(entry.path + ": " + str(self._englLangTest(entry.path)))
        return