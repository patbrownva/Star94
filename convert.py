import sys
import argparse
from os.path import join,basename,splitext
from time import strftime
from datetime import datetime, timedelta
import subprocess
import locale
import re
from functools import reduce

def parse_duration(duration_string):
    return reduce(lambda a,b: a*60+b, map(float, duration_string.split(':')), 0)

def parse_interval(interval_string):
    """Takes an interval string from the config and turns it into a :class:`datetime.timedelta` object."""
    regexp = r'^\d+ (second|minute|hour|day|week)s?$'
    if not re.match(regexp, interval_string):
        raise ValueError("should be in format 'x (seconds|minutes|hours|days|weeks)'")
    """Parse a string like '5 days' into a timedelta object. Also allows timedeltas to pass through."""
    amount, unit = interval_string.lower().split(' ')
    # Make sure unit name is plural.
    if not unit.endswith('s'):
        unit += 's'
    params = {unit: float(amount)}
    try:
        return timedelta(**params)
    except TypeError:
        raise ValueError('Invalid time format \'%s\'' % value)

def parse_datetime(date_string):
    try:
        interval = parse_interval(date_string)
        return datetime.today() + interval
    except ValueError:
        pass
    date_formats = ['%d/%m/%Y %H:%M:%S',
                    '%d/%m/%y %H:%M:%S',
                    '%d-%m-%Y %H:%M:%S',
                    '%Y/%m/%d %H:%M:%S',
                    '%Y-%m-%d %H:%M:%S']
    for df in date_formats:
        try:
            return datetime.strptime(date_string, df)
        except ValueError:
            continue
    raise ValueError('invalid date `%s`' % date_string)
    

SILENCE_START = re.compile(r"] silence_start: ([0-9.]+)", re.M)
SILENCE_END = re.compile(r"] silence_end: ([0-9.]+)", re.M)
DURATION = re.compile(r"^ *Duration: ([0-9:.]+)", re.M)
FFMPEG_PATH = "C:\\Users\\PROPHET\\flexget\\ffmpeg.exe"
def execute_cmd(*args):
    response = subprocess.check_output(args, stderr=subprocess.STDOUT, text=True)
    return response

SPOT_TYPES = {'SPOT':1, 'SHOWS':8}
cmdline = argparse.ArgumentParser()
cmdline.add_argument('-cart', type=int)
cmdline.add_argument('-cut', type=int, default=1)
cmdline.add_argument('-title')
cmdline.add_argument('-type', default='SPOT', choices=SPOT_TYPES.keys())
cmdline.add_argument('-enddate', type=parse_datetime, default="01/01/2099 00:00:00")
cmdline.add_argument('-clip', type=int, default=-1)
cmdline.add_argument('source')
cmdline.add_argument('dest')
args = cmdline.parse_args(sys.argv[1:])
if not args.title:
    args.title = splitext(basename(args.source))[0]

silenceoutput = execute_cmd(FFMPEG_PATH,
                            "-hide_banner",
                            "-i", args.source,
                            "-filter:a", "silencedetect=-30dB:d=0.76",
                            "-f", "null", "-"
                            )
length = parse_duration(DURATION.search(silenceoutput).group(1))
offset = 0.0
seconds = length
try:
    silence_splits = [*zip(SILENCE_START.findall(silenceoutput),
                           SILENCE_END.findall(silenceoutput))]
    if len(silence_splits) > 0:
        silence_clip = args.clip
        if silence_clip <= 0 or silence_clip >= len(silence_splits):
            if seconds - float(silence_splits[-1][1]) < 0.76:
                seconds = float(silence_splits[-1][0])
        else:
            seconds = float(silence_splits[silence_clip][0])
        if float(silence_splits[0][0]) < 1.76:
            offset = float(silence_splits[0][1])
        if seconds > offset:
            length = seconds - offset
        else:
            length = 0.76
except (AttributeError,IndexError):
    pass

analyzeoutput = execute_cmd(FFMPEG_PATH,
                            "-hide_banner",
                            "-i", args.source,
                            "-t", f"{length:.4}s",
                            "-ss", f"{offset:.4}s",
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
                       "-i", args.source,
                       "-t", f"{length:.4}s",
                       "-ss", f"{offset:.4}s",
                       "-filter:a", "volume={:.1}dB".format(round(volume,1)),
                       "-c:a", "mp2",
                       "-b:a", "256k",
                       args.dest
                       )

if not args.cart:
    sys.exit(0)

with open(splitext(args.dest)[0]+".xml", 'w', encoding=locale.getpreferredencoding()) as xml:
    xml.write(f"""<XMLDAT>
    <Version>1</Version>
    <Cart>{args.cart}</Cart>
    <Cut>{args.cut}</Cut>
    <Type>{SPOT_TYPES[args.type]}</Type>
    <Category>Spots</Category>
    <Title>{args.title}</Title>
    <Start_Time>02/10/2020 00:00:00</Start_Time>
    <End_Time>{args.enddate.strftime('%m/%d/%Y %H:%M:%S')}</End_Time>
    <Archive_Time>01/01/2099 00:00:00</Archive_Time>
    <Modified_Time>{strftime('%m/%d/%Y %H:%M:%S')}</Modified_Time>
    <File_Name>{basename(args.dest)}</File_Name>
    <Length>{int(length*1000)}</Length>
    <Intro_3>0</Intro_3>
    <Outro>0</Outro>
    <Intro_Start>0</Intro_Start>
    <Outro_Start>0</Outro_Start>
    <Cross_Fade>0</Cross_Fade>
    <Comments></Comments>
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
