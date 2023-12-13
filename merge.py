from wavfilelength import wavfilelength
import sys
from os.path import join,basename,splitext
from time import strftime
import subprocess
import locale
import re

FFMPEG_PATH = "C:\\Users\\PROPHET\\flexget\\ffmpeg.exe"
def execute_cmd(*args):
    response = subprocess.check_output(args, stderr=subprocess.STDOUT, text=True)
    return response
    #proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    #response = proc.stdout.read()
    #proc.stdout.close()
    #return proc.wait(), response

names = [splitext(basename(p))[0].split(' ')[-1] for p in sys.argv[1:]]
if not names:
    sys.exit(0)
if len(names) == 1:
    dest = names[0]
    source = sys.argv[1]
else:
    source = "concat:"+"|".join(sys.argv[1:])
    dest = "_".join(names)

dest = join("D:\\Library", dest + ".wav")
analyzeoutput = execute_cmd(FFMPEG_PATH,
                            "-hide_banner",
                            "-i", source,
                            "-filter:a", "volumedetect",
                            "-f", "null", "-"
                            )
if match := re.search(r'mean_volume: (-?\d+(?:\.\d+)?) dB',analyzeoutput):
    volume = -20.0 - float(match.group(1))
else:
    volume = 0
response = execute_cmd(FFMPEG_PATH,
                       "-hide_banner",
                       "-y",
                       "-i", source,
                       "-filter:a", "volume={:.1}dB".format(round(volume,1)),
                       "-c:a", "mp2",
                       "-b:a", "256k",
                       dest
                       )

try:
    cart = int(input("Cart number: "))
    title = input("Title: ").strip()
    comment = input("Times: ").strip()
except (EOFError,ValueError):
    sys.exit(0)
length = wavfilelength(dest)
time = strftime("%m/%d/%Y %H:%M:%S")
with open(splitext(dest)[0]+".xml", 'w', encoding=locale.getpreferredencoding()) as xml:
    xml.write(f"""<XMLDAT>
    <Version>1</Version>
    <Cart>{cart}</Cart>
    <Cut>1</Cut>
    <Type>1</Type>
    <Category>Spots</Category>
    <Title>{title}</Title>
    <Start_Time>02/10/2020 00:00:00</Start_Time>
    <End_Time>01/01/2099 00:00:00</End_Time>
    <Archive_Time>01/01/2099 00:00:00</Archive_Time>
    <Modified_Time>{time}</Modified_Time>
    <File_Name>{basename(dest)}</File_Name>
    <Length>{int(length*1000)}</Length>
    <Intro_3>0</Intro_3>
    <Outro>0</Outro>
    <Intro_Start>0</Intro_Start>
    <Outro_Start>0</Outro_Start>
    <Cross_Fade>0</Cross_Fade>
    <Comments>{comment}</Comments>
    <Erase_Time>01/01/2099 00:00:10</Erase_Time>
    <Replay>0</Replay>
    <User_Define></User_Define>
    <Fade>0</Fade>
    <Fade_Up_Start>-1</Fade_Up_Start>
    <Fade_Up_Length>-1</Fade_Up_Length>
    <Fade_Down_Start>-1</Fade_Down_Start>
    <Fade_Down_Length>-1</Fade_Down_Length>
    <Intro_1>0</Intro_1>
    <Intro_2>0</Intro_2>
    <AudioNotes></AudioNotes>
    <ProductionType>0</ProductionType>
    <ISCI_Code></ISCI_Code>
    <Brand></Brand>
    <Keywords></Keywords>
    <Out_Cue></Out_Cue>
    <MediaStartSpotId>0</MediaStartSpotId>
    <MediaStartCartId>0</MediaStartCartId>
</XMLDAT>
""")
