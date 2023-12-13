from struct import unpack
from chunk import Chunk

def wavfilelength(filename):
    wavfile = open(filename, 'rb')
    head = wavfile.read(12)
    if head[0:4]!=b'RIFF' or head[8:12]!=b'WAVE':
        raise ValueError("Not a WAV file.")
    wav = Chunk(wavfile, align=False, bigendian=False)
    if wav.getname()!=b'fmt ':
        raise ValueError("Improperly formatted WAV file.")
    fmt = unpack('HHIIHH', wav.read(16))
    wav.skip()
    length = None
    try:
        while not length:
            ext = Chunk(wavfile, align=False, bigendian=False)
            if ext.getname()==b'data':
                #if fmt[0]!=1:
                #    raise ValueError("WAV file is not PCM but doesn't have fact header.")
                length = ext.getsize() / fmt[4] / fmt[2]
            elif ext.getname()==b'fact':
                length = unpack('I', ext.read(4))[0] / fmt[2]
    except EOFError:
        raise ValueError("Unexpected EOF reading WAV file.")
    return length

if __name__=='__main__':
    import sys
    from glob import glob
    from itertools import chain
    if len(sys.argv)==2 and not ('*' in sys.argv[1] or '?' in sys.argv[1]):
        print("%.3f" % wavfilelength(sys.argv[1]))
    else:
        for fn in chain(*(glob(arg) for arg in sys.argv[1:])):
            print("%s: %.3f" % (fn, wavfilelength(fn)))
