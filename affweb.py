from json import JSONDecoder
from bs4 import BeautifulSoup
import requests
from ftplib import FTP, all_errors as ftp_errors
from os import remove as removefile
from os.path import splitext, join as joinpath, getmtime
from glob import glob
import re
from time import localtime,strptime,strftime
from datetime import datetime,timedelta
import subprocess
import locale
from struct import unpack
from chunk import Chunk
from urllib.parse import urlencode

SIMULATE = False

Carts = {
    'Agency|AML': ('Premiere', 'Alpha Music Libraries - 28 Minute', 1101,
                   ('',)),
    'Agency|ProductionVault': ('Premiere', 'Production Vault Classic Rock - 28 Minute', 1144,
                               ('',)),
#    'Agency|Securenet': ('USRN', 'Securenet M', 1201,
#                         ('Morning', 'Afternoon')),
    'Agency|VeriAds': ('Westwoodone', 'Veritone - VeriAds ROS', 1201,
                      ('Morning', 'Afternoon')),
#    'Agency|MANN': ('CompassMedia', 'MANN Issues Today Weekend', 1275,
#                    ('', '', '', '', '')),
    'Agency|MSB': ('CompassMedia', 'CM Ron Insana Mkt Score Board', 1215,
               ('Morning', 'Evening')),
#    'Agency|AdImpact': ('CompassMedia', 'Ad Impact', 1225,
#                    ('',)),
    'Agency|BDP FM': ('Westwoodone', '_S16 Brandon DAmore 17G Oldies', 1230,
                      ('Morning', 'Afternoon')),
    'Agency|BDP AM': ('WestwoodoneAM', '_D5 BDP Brandon DAmore Male_A', 1244,
                      ('Morning', 'Afternoon')),
    'Agency|Audio Clip Art': ('Westwoodone', '_D3 Audio Clip Art 15FAS_A', 1258,
                              ('',)),
    'Agency|Audio Clip Art Weekend': ('Westwoodone', 'CLA Audio Clip Art 67FYS_A', 1263,
                                      ('',)),
    'Agency|Adrenaline (Evening)': ('WestwoodoneAM', 'CLA Adrenaline 17GAC_A', 1265,
                                    ('',)),
    'Agency|Adrenaline (Morning)': ('WestwoodoneAM', '_D2 Adrenaline 17FMS_A', 1270,
                                    ('',)),
    }

Delivery = {
    'Agency|AML': 'Premiere Networks/Alpha Music Libraries - 28 Minute',
    'Agency|ProductionVault': 'Premiere Networks/Production Vault Classic Rock - 28 Minute',
    'Agency|Securenet': 'AIM/Securenet M*',
#    'Agency|AdImpact': 'WestwoodOne Delivery/**',
    'Agency|Audio Clip Art': 'WestwoodOne Delivery/_D3 Audio Clip Art 15FAS_A',
    'Agency|Audio Clip Art Weekend': 'WestwoodOne Delivery/CLA Audio Clip Art 67FYS_A',
    'Agency|MSB': 'WestwoodOne Delivery/CM Ron Insana Mkt Score Board',
    'Agency|BDP FM': 'WestwoodOne Delivery/_S16 Brandon DAmore 17G Oldies',
    'Agency|BDP AM': 'WestwoodOne Delivery/_D5 BDP Brandon DAmore Male_A',
#    'Agency|MANN': 'WestwoodOne Delivery/MANN Issues Today Weekend',
    'Agency|Adrenaline (Morning)': 'WestwoodOne Delivery/_D2 Adrenaline 17FMS_A',
    'Agency|Adrenaline (Evening)': 'WestwoodOne Delivery/CLA Adrenaline 17GAC_A',
    'Agency|VeriAds': 'WestwoodOne Delivery/Veritone - VeriAds ROS',
    }

Servers = {
    'USRN': ('LOGIN-REMOVED', 'PASSWORD-REMOVED', 'http://affiliate1.counterpoint.net/AffWeb_USRN/V2/ASP/GTD.asp',1),
    'CompassMedia': ('LOGIN-REMOVED', 'PASSWORD-REMOVED', 'http://affiliate1.counterpoint.net/AffWeb_CompassMedia/V2/ASP/GTD.asp',1),
    'Westwoodone': ('LOGIN-REMOVED', 'PASSWORD-REMOVED', 'https://affiliate.westwoodone.com/AffWeb/Home/RunCommand',0),
    'WestwoodoneAM': ('LOGIN-REMOVED', 'PASSWORD-REMOVED', 'https://affiliate.westwoodone.com/AffWeb/Home/RunCommand',0),
    }

PNURL = "https://www.premiereaffidavits.com/"
WService = PNURL+"scripts/cgiip.exe/WService=webprime/"
PNAPI = "https://api.premiereaffidavits.com/"

FTPServer = '192.168.129.75'
FTPPath = 'assets/Spots'
FTPDestination = 'D:\\INBOX'

FFMPEG_PATH = 'C:\\Users\PROPHET\\flexget\\ffmpeg.exe'
InboxPath = 'D:\\INBOX'
OutputPath = 'D:\\OUTBOX'

def writeXMLDat(filename, cart, title, starttime, endtime, modtime, length, comment):
    if SIMULATE:
        print(f"Would write XML to {filename} ({comment}).")
        return
    with open(joinpath(OutputPath,splitext(filename)[0]+".xml"), 'w', encoding=locale.getpreferredencoding()) as xml:
        xml.write(f"""<XMLDAT>
    <Version>1</Version>
    <Cart>{cart}</Cart>
    <Cut>1</Cut>
    <Type>1</Type>
    <Category>Spots</Category>
    <Title>{title}</Title>
    <Start_Time>{starttime}</Start_Time>
    <End_Time>{endtime}</End_Time>
    <Archive_Time>01/01/2099 00:00:00</Archive_Time>
    <Modified_Time>{modtime}</Modified_Time>
    <File_Name>{filename}</File_Name>
    <Length>{length}</Length>
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

VOLUMEDETECT_RE = re.compile(r'mean_volume: (-?\d+(?:\.\d+)?) dB')
def convertMP2(filename, sourcefiles):
    if len(sourcefiles) == 1:
        source = sourcefiles[0]
    else:
        source = "concat:"+"|".join(sourcefiles)
    if SIMULATE:
        print(f"Would convert \"{source}\" to {filename}.")
        return
    analyzeoutput = execute_cmd(FFMPEG_PATH,
                                "-hide_banner",
                                "-i", source,
                                "-filter:a", "volumedetect",
                                "-f", "null", "-"
                                )
    if match := VOLUMEDETECT_RE.match(analyzeoutput):
        volume = -20.0 - float(match.group(1))
    else:
        volume = 0.0
    execute_cmd(FFMPEG_PATH,
                "-hide_banner",
                "-y",
                "-i", source,
                "-filter:a", "volume={:.1}dB".format(round(volume,1)),
                "-c:a", "mp2",
                "-b:a", "256k",
                joinpath(OutputPath, filename)
                )

def wavfilelength(filename):
    if SIMULATE:
        return 60.0
    wavfile = open(joinpath(OutputPath, filename), 'rb')
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

VALIDPATH_RE = re.compile(r'[^-A-Za-z0-9_]')
def cleanfilename(filename):
    return VALIDPATH_RE.sub("", filename.replace(" ", "_"))

def convertdate(datestr):
    for form in ("%m/%d/%Y", "%m/%d/%y", "%Y/%m/%d"):
        try:
            t = strptime(datestr, form)
            return strftime("%Y/%m/%d", t)
        except ValueError:
            pass
    raise ValueError(f"invalid date string '{datestr}'")

FIX_AMPM_RE = re.compile(r'([AP])M?')
def converttime(timestr):
    timestr = FIX_AMPM_RE.sub(r' \1M', timestr)
    for form in ("%I:%M:%S %p", "%I:%M %p", "%H:%M:%S", "%H:%M"):
        try:
            t = strptime(timestr, form)
            return strftime("%H:%M:%S", t)
        except ValueError:
            pass
    raise ValueError(f"invalid time string '{timestr}'")

def sanitizedate(datestr):
    for form in ("%m/%d/%Y", "%m/%d/%y", "%Y/%m/%d"):
        try:
            t = strptime(datestr, form)
            return strftime("%m/%d/%Y", t)
        except ValueError:
            pass
    try:
        t = strptime(datestr, "%m/%d")
        dstr = strftime("%m/%d/%Y", localtime()[:1]+t[1:])
        strptime(dstr, "%m/%d/%Y") # check again for out-of-range dates
        return dstr
    except ValueError:
        pass
    try:
        t = strptime(datestr, "%d")
        dstr = strftime("%m/%d/%Y", localtime()[:2]+t[2:])
        strptime(dstr, "%m/%d/%Y") # check again for out-of-range dates
        return dstr
    except ValueError:
        pass
    raise ValueError(f"invalid date string '{datestr}'")

def datespan(date1, date2):
    t1 = strptime(date1, "%m/%d/%Y")
    t2 = strptime(date2, "%m/%d/%Y")
    diff = t2.tm_yday - t1.tm_yday
    if t2.tm_year != t1.tm_year:
        diff += strptime("12/31/"+str(t1.tm_year), "%m/%d/%Y").tm_yday
        if diff > 365 or t2.tm_year-t1.tm_year > 1:
            raise ValueError("If this is counting more than a year at a time something is wrong.")
    return diff

DAYSOFWEEK = ('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
def day_of_week(day):
    return DAYSOFWEEK.index(day) 

def execute_cmd(*args):
    if SIMULATE:
        raise RuntimeError("Exec not available in simulation.")
    response = subprocess.check_output(args, stderr=subprocess.STDOUT, text=True)
    return response
    #response = proc.stdout.read()
    #proc.stdout.close()
    #return proc.wait(), response

def downloadFromFTP(names):
    if SIMULATE:
        print(f"Downloading from FTP.")
    #    return [name+".MP2" for name in names]
    downloaded = {}
    try:
        with FTP(FTPServer) as session:
            session.login()
            session.cwd(FTPPath)
            if SIMULATE:
                try:
                    nlist = set(session.nlst())
                    files = nlist.intersection(name+".MP2" for name in names)
                    downloaded = {name: joinpath(FTPDestination,name+".MP2")
                                  for name in names if name+".MP2" in files}
                except ftp_errors:
                    pass
            else:
                for name in names:
                    filename = name+".MP2"
                    fullname = joinpath(FTPDestination, filename)
                    try:
                        with open(fullname, 'wb') as output:
                            session.retrbinary("RETR "+filename, output.write)
                        downloaded[name] = fullname
                    except ftp_errors as err:
                        print("Skipping {}: {}".format(name, err))
                        try:
                            removefile(fullname)
                        except OSError:
                            pass
    except ftp_errors as err:
        pass
    return downloaded

def getFilesystemPath(cartName, spotNames):
    if SIMULATE:
        print(f"Searching in \"{joinpath(InboxPath,Delivery[cartName])}\".")
    #    return {name:joinpath(InboxPath, Delivery[cartName], name+".*") for name in spotNames}
    searchPath = joinpath(InboxPath, Delivery[cartName], "*{}.*")
    files = {}
    for name in spotNames:
        try:
            files[name] = sorted(glob(searchPath.format(name)),
                                 key=getmtime).pop()
        except IndexError:
            pass
    return files

ROWID_RE = re.compile(r'window\.location\.href="[\w.]*\?rowid=(0x[0-9A-Fa-f]+)"')
def get_table(html):
    table = BeautifulSoup(html, 'html5lib').find('table', class_='table')
    if not table:
        raise ValueError("Couldn't find table.")
    headers = tuple(td.get_text().strip() for td in table.find_all('th'))
    def _get_row(row):
        data = tuple(td.get_text().strip() for td in row.find_all('td'))
        return dict(zip(headers, data)) if headers else data
    return [_get_row(row) for row in table.find_all('tr') if row.find('td')]

class PremiereNetworks:

    session = None
    row_id = None

    def __init__(self):
        self.session = requests.Session()

    def login(self, name, password):
        response = self.session.post(WService+"login.html",
                                     data={'B1':'Submit', 'login':name, 'password':name})
        response.raise_for_status()
        if m := ROWID_RE.search(response.text):
            self.row_id = m.group(1)
            return True
        return False

    def logout(self):
        self.session.get(WService+"login.html", params={'rowid':self.row_id})
        self.row_id = None

    def shows(self):
        response = self.session.get(WService+"shows.html", params={'rowid':self.row_id})
        response.raise_for_status()
        return get_table(response.content)

    # date format is %m/%d/%y
    def affidavit(self, name, start_date=None, start_week=None):
        response = self.session.get(WService+"schedule.html", params={'rowid':self.row_id})
        response.raise_for_status()
        for row in get_table(response.content):
            if row['Show Title'] == name:
                if ((start_date and row['Week Of Date'] == start_date)
                or (start_week and row['Week'] == start_week)):
                    return row['Spot Detail']
        return None

    def schedule(self, affidavit_num):
        response = self.session.get(WService+"schedspots.html",
                                    params={'rowid':self.row_id, 'AFFIDAVITNO':affidavit_num})
        response.raise_for_status()
        return get_table(response.content)

class PremiereNetworksREST:

    session = None
    affiliate_id = None

    def __init__(self):
        self.session = requests.Session()

    def login(self, name, password):
        response = self.session.post(PNAPI+"token", verify=True,
                                     json={'userName':name, 'password':name})
        response.raise_for_status()
        token = response.json()
        if 'access_token' in token:
            self.session.headers['Authorization'] = token['token_type'].title() + " " + token['access_token']
            self.affiliate_id = token['affiliateId']
            return True
        return False

    def logout(self):
        #self.session.get(WService+"login.html", params={'rowid':self.row_id})
        self.token = None

    def shows(self):
        response = self.session.post(PNAPI+"show", verify=True,
                                     json={'affiliateId':self.affiliate_id})
        response.raise_for_status()
        return response.json()

    ## date format is %m/%d/%y
    #def affidavit(self, name, start_date=None, start_week=None):
    #    response = self.session.get(WService+"schedule.html", params={'rowid':self.row_id})
    #    response.raise_for_status()
    #    for row in get_table(response.content):
    #        if row['Show Title'] == name:
    #            if ((start_date and row['Week Of Date'] == start_date)
    #            or (start_week and row['Week'] == start_week)):
    #                return row['Spot Detail']
    #    return None

    def schedule(self, name, start_date=None):
        response = self.session.post(PNAPI+"schedule", verify=True,
                                     json={'affiliateId':self.affiliate_id})
        response.raise_for_status()
        schedules = [sched for sched in response.json() if sched['show'] == name]
        if start_date:
            response = self.session.post(PNAPI+"broadcastweek", verify=True,
                                         json={'broadcast':start_date})
            broadcastweek = response.json()
            if 'errors' not in broadcastweek:
                broadcastweek = broadcastweek[0]
                schedules = [sched for sched in schedules if sched['week'] == broadcastweek['week'] and sched['year'] == broadcastweek['year']]
        all_spots = []
        for sched in schedules:
            #print(f">>scedule/{sched['scheduleId']}")
            response = self.session.get(PNAPI+f"schedule/{sched['scheduleId']}",
                                        verify=True)
            response.raise_for_status()
            if 'errors' not in response.json():
                all_spots.extend(response.json()['spots'])
        return all_spots

def getSchedSpots(vehicle_name, start_date, end_date):
    network = PremiereNetworksREST()
    if not network.login("10177", "10177"):
        return []
    try:
        start_time = strptime(start_date, '%m/%d/%Y')
        end_time = strptime(end_date, '%m/%d/%Y')
        ## Seems Premiere schedules based on the affidavit due date.
        #week_time = (datetime(*start_time[:7]) + timedelta(days=6)).timetuple()
        #start_week = strftime('%U', week_time)
        weekdays = range(start_time.tm_wday, end_time.tm_wday + 1)
        all_spots = (spot for spot in network.schedule(vehicle_name, strftime("%Y-%m-%d", start_time))
                    if day_of_week(spot['dayOfWeek']) in weekdays)
        #def _fix_keys(spot):
        #    spot['ISCI'] = spot['Commercial']
        #    del spot['Commercial']
        #    spot['Pledge Time'] = spot['Pledgetime']
        #    del spot['Pledgetime']
        #    pledge_date = strptime("{}{}{}".format(
        #        start_time.tm_year, start_week, (day_of_week(spot['Day Of Week'])+1)%7),
        #        '%G%V%w')
        #    spot['Pledge Date'] = strftime('%Y/%m/%d', pledge_date)
        #    return spot
        #return [_fix_keys(spot) for spot in all_spots]
        return list(all_spots)
    finally:
        network.logout()

def safedict(tuples):
    table = dict()
    for k,v in tuples:
        if k not in table:
            table[k] = v
        #else merge new value?
    return table

def GTDecoder(data):
    if data == 'ENDOFDATA':
        return []
    json = JSONDecoder()
    decoded = json.decode('['+data+']')
    keys = decoded[0]
    return ( safedict(zip(keys,map(str.rstrip,row))) for row in decoded[1:] )

def spGetAllSpots(networkName, attName, startDate, endDate):
    stationName,stationPW,attServer,sqlVersion = Servers[networkName]
    if sqlVersion < 1:
        command = ["25",stationName,attName,startDate,endDate,""]
        response = runCommand(stationName, stationPW, attServer, command)
    else:
        sql_cmd = f"spGetAllSpots '{stationName}','{attName}','{startDate}','{endDate}'"
        if sqlVersion > 1:
            sql_cmd += ",''"
        response = sqlCmd(stationName, stationPW, attServer, sql_cmd)
    return (spot for spot in response)

def runCommand(stationName, stationPW, attServer, command):
    response = requests.post(attServer, verify=True,
                             data=[(b"myArray[]",field.encode("UTF-8")) for field in command],
                             headers={'Content-Type':"application/x-www-form-urlencoded"},
                             cookies={'StationName':stationName,'Password':stationPW})
    response.raise_for_status()
    return GTDecoder(response.text)

def sqlCmd(stationName, stationPW, attServer, sql_cmd):
    response = requests.get(attServer, verify=True,
                            params={'SQLCMD':sql_cmd},
                            cookies={'StationName':stationName,'Password':stationPW})
    response.raise_for_status()
    return GTDecoder(response.text)


def modifySpotAddDate(spot):
    spot['date'] = convertdate(spot['Pledge Date']) + " " + converttime(spot['Pledge Time'])
    spot['skip'] = False
    return spot

def collectVehicle(cartName, startDate, endDate):
    spotblocks = []
    networkName, vehicleName, spotNumber, spotNames = Carts[cartName][0:4]
    if networkName == 'Premiere':
        all_spots = getSchedSpots(vehicleName, startDate, endDate)
        spots_by_days = {day:[spot for spot in all_spots if spot['dayOfWeek']==day]
                            for day in set(sp['dayOfWeek'] for sp in all_spots)}
        for day_spots in (spots_by_days[day] for day in DAYSOFWEEK if day in spots_by_days):
            # times are 12 hours but A sorts before P and there should never be a time at 12 AM
            first_spot = min(day_spots, key=lambda spot: spot['pledgeTime'])
            spot_list = []
            for spot in day_spots:
                if spot['pledgeTime'] == first_spot['pledgeTime']:
                    print("({}) {} [{}]".format(spot['pledgeTime'], spot['advertiser'], spot['commercial']))
                    spot_list.append((spot['advertiser'],spot['commercial']))
            #spot_list = [(spot['advertiser'],spot['commercial']) for spot in day_spots
            #                if spot['pledgeTime']==first_spot['pledgeTime']]
            spotblocks.append(spot_list)
            spot_codes = [spot[1] for spot in spot_list]
            additional_times = set(spot['pledgeTime'] for spot in day_spots
                                    if spot['commercial'] not in spot_codes)
            for block_time in sorted(additional_times, key=converttime):
                spot_list = []
                for spot in day_spots:
                    if spot['pledgeTime'] == block_time:
                        print("({}) {} [{}]".format(spot['pledgeTime'], spot['advertiser'], spot['commercial']))
                        spot_list.append((spot['advertiser'],spot['commercial']))
                if spot_list:
                    spotblocks.append(spot_list)
                #spotblocks.append([(spot['advertiser'],spot['commercial']) for spot in day_spots
                #                    if spot['pledgeTime']==block_time])

    else:
        spotlog = [modifySpotAddDate(spot) for spot in spGetAllSpots(networkName, vehicleName, startDate, endDate)]
        spotlog.sort(key = lambda spot: spot['date'])
        for i, spot in enumerate(spotlog):
            print("({}) {} [{}]".format(spot['date'], spot['Advt / Prod'], spot['ISCI']))
            if not spot['skip']:
                if spot['date'].endswith(":00"):
                    truncatedtime = spot['date'][0:-3]
                    seencodes = set((spot['ISCI'],))
                    additionalcodes = []
                    for successive in (nextspot for nextspot in spotlog[i+1:] if not nextspot['skip']):
                        if successive['date'].startswith(truncatedtime):
                            if successive['ISCI'] not in seencodes:
                                additionalcodes.append((successive['Advt / Prod'],successive['ISCI']))
                                seencodes.add(successive['ISCI'])
                                successive['skip'] = True
                        else:
                            break
                    spotblocks.append(((spot['Advt / Prod'],spot['ISCI']),*additionalcodes))
                else:
                    spotblocks.append(((spot['Advt / Prod'],spot['ISCI']),))

    numDays = datespan(startDate, endDate) + 1
    spotNames *= numDays
    if len(spotblocks) != len(spotNames):
        print("WARNING: processed {} spots for {} (expected {}).".format(len(spotblocks), cartName, len(spotNames)))
    return (((cartName+" "+name).strip(),number,tuple(sp[1] for sp in spot)," | ".join(sp[0] for sp in spot))
            for name,number,spot in zip(spotNames, range(spotNumber, spotNumber+len(spotNames)), spotblocks))

def main(vehicleName, startDate, endDate):
    collectedSpots = list(collectVehicle(vehicleName, startDate, endDate))
    collectedCodes = set(sum((spot[2] for spot in collectedSpots), start=()))
    #availableFiles = downloadFromFTP(collectedCodes)
    availableFiles = getFilesystemPath(vehicleName, collectedCodes)
    if len(availableFiles) != len(collectedCodes):
        availableFiles.update(
            downloadFromFTP(collectedCodes.difference(availableFiles)))
    if len(availableFiles) != len(collectedCodes):
        print(f"WARNING: Missing files for {vehicleName}: {' '.join(collectedCodes.difference(availableFiles))}")
    duplicateFiles = set()
    for spot in collectedSpots:
        print(f"[{spot[1]}]{spot[0]}: {','.join(spot[2])}")
        spotName,spotNumber = spot[0:2]
        spotCodes = [name for name in spot[2] if name in availableFiles]
        if not spotCodes:
            print("No files available for {} ({}).".format(spotName, spotNumber))
        else:
            filename = cleanfilename(spotName)
            suffix = 0
            while filename in duplicateFiles:
                filename = cleanfilename(spotName) + "_" + str(len(duplicateFiles)+suffix)
                suffix += 1
            duplicateFiles.add(filename)
            filename += ".wav"
            convertMP2(filename, [availableFiles[name] for name in spotCodes])
            wavLength = wavfilelength(filename)
            writeXMLDat(filename,
                        spotNumber,
                        spotName,
                        startDate + " 00:00:00",
                        startDate + " 23:59:59",
                        strftime("%m/%d/%Y %H:%M:%S"),
                        int(wavLength*1000),
                        spot[3]
                        )

if __name__=='__main__':
    import sys
    import traceback
    if "-s" in sys.argv:
        SIMULATE = True
        sys.argv.remove("-s")
    startDate = None
    endDate = None
    if len(sys.argv) <= 1:
        startDate = strftime("%m/%d/%Y")
        cartList = Carts.keys()
    elif len(sys.argv) == 2:
        startDate = sanitizedate(sys.argv[1])
        cartList = Carts.keys()
    else:
        startDate = sanitizedate(sys.argv[2])
        cartList = sys.argv[1:2]
    if startDate is None:
        startDate = strftime("%m/%d/%Y")
    for vehicleName in cartList:
        try:
            main(vehicleName, startDate, startDate)
        except:
            traceback.print_exc()

