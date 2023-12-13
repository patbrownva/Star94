
def findany(S, Ps):
    for P in Ps:
        if M:=re.search(P, S):
            return M.start()
    return -1

Columns = {}
Log = []
Hour = []
Spots = {}

IsMonday = True
IsAM = False
Trafficlog = None
LogName = None

import sys
import re
import math
import time
import random

#class MockRandom:
#    def __init__(self, filename):
#        self.randompool = open(filename, 'rb')
#    def random(self):
#        return ord(self.randompool.read(1)) / 256
#random = MockRandom("randompool")

Warnings = 0
def warning(S, *args):
    global Warnings, LogName
    Warnings += 1
    if LogName:
        sys.stderr.write(LogName+":")
    sys.stderr.write(S.format(*args))

def rotatetable(T):
    T.sort(key=lambda x: x["rotate"])

def today():
    return 24*60*60 - 1 + time.time()

def isexpired(date):
    M = re.match(r'(\d+)/(\d+)/(\d+)', date)
    if M:
        month,day,year = map(int,M.groups())
        return time.mktime((year,month,day,0,0,0,0,0,0)) - today() < 0
    return True

def readline(file):
    return file.readline().rstrip("\r\n")

def renderseconds(sec):
    dec = math.floor(((sec + 0.05) * 10) % 10)
    min = math.floor(sec / 60)
    sec = math.floor(sec) % 60
    return "{:02}:{:02}:{}".format(min,sec,dec)

def renderminutes(sec, estimate=False):
    hr = math.floor(sec / 3600)
    sec = sec - hr*3600
    min = math.floor(sec / 60)
    sec = math.floor(sec + 0.5) % 60
    return "{:02}:{:02}:{:02}{}".format(hr,min,sec,"-E" if estimate else "")

def readseconds(S):
    M = re.match(r"(\d+):(\d+[:\.]\d+)", S)
    if M:
        return float(M.group(1))*60 + float(M.group(2).replace(":","."))
    return None

def readminutes(S):
    M = re.match(r"(\d+):(\d+):(\d+)", S)
    if M:
        hr,min,sec = map(float,M.groups())
        return hr*3600 + min*60 + sec

def renderspotcut(spotnum, cutnum):
    return "{:07}-{:03}".format(spotnum,cutnum)

def rendertraffic(C):
    shortdescription = re.match(r"^(.*?)(?:\|.*)?", C["Description"]).group(1)
    if not shortdescription:
        shortdescription = C["Description"]
    num = int(C["Number"])
    if num > 1000000:
        num = "F{:05}".format((num - 1200000)%100000)
    else:
        num = "{:06}".format(num)
    return "    |{}|{}|{:<17}|{:<30}|{:>4}\n".format(C["Start Time"],
                                                       num,
                                                       shortdescription[:17],
                                                       C["Description"][:30],
                                                       C["Length"])

def rendertrafficblock(starttime, description=None):
    if description is None:
        description = "BLOCK #"
    return "    |{}|      |                 |{:<30}|    \n".format(starttime, description)

def rendercolumn(C):
    line = [C.get(name,"").ljust(pos[1] - pos[0]) for name,pos in Columns.items()]
    return "".join(line)

def renderheader():
    line = [name.ljust(pos[1] - pos[0]) for name,pos in Columns.items()]
    return "".join(line)

def readheader(file):
    C = {}
    line = readline(file)
    if line:
        for M in re.finditer("(([ -~]+?)  +)", line):
            name = M.group(2)
            C[name] = M.span()
    return C

def readcolumn(C, line, name):
    pos = C[name]
    S = line[pos[0]:pos[1]].rstrip()
    if not S:
        return None
    return S

def readallcolumns(Columns, line):
    C = {}
    for name,pos in Columns.items():
        S = line[pos[0]:pos[1]].rstrip()
        C[name] = S #if S else None
    return C

def readspotnumcut(S):
    spotnum,cutnum = re.match(r"(-?\d+)-(-?\d+)", S).groups()
    return int(spotnum or 0), int(cutnum or 0)

def readspotlist(file):
    Spots = {}
    Columns = readheader(file)
    while line:=readline(file):
        Spot = readallcolumns(Columns, line)
        if not isexpired(Spot["End Date"]):
            spotnum,cutnum = readspotnumcut(Spot["Spot,Cut"])
            length = readseconds(Spot["Length"])
            if spotnum not in Spots:
                Spots[spotnum] = []
            Spots[spotnum].append({"numcut": (spotnum,cutnum),
                                   "description": Spot["Spot Title"],
                                   "category": Spot["Category"],
                                   "length": length})
    return Spots

def canfitspot(cart, fill):
    for spot in cart:
        if spot["length"] < fill:
            return spot
    return None

def readspotblock(file, time, length):
    global Hour
    global Log
    Spotblock = {
        "Description": "SPOT BLOCK",
        "Start Time": renderminutes(time, True),
        "Length": renderseconds(length),
        "length": length,
        "time": time,
        "spots": [],
        "trafficfillposition": None,
        "blockfillposition": None
    }
    while line:=readline(file):
        description = readcolumn(Columns, line, "Description")
        spot = readallcolumns(Columns, line)
        if not ("NBC29 LOCAL NEWS" in spot["Description"] and IsMonday):
            Spotblock["spots"].append(spot)
            if spot["Description"] == "END BLOCK":
                if Spotblock["trafficfillposition"] is not None:
                    Spotblock["blockfillposition"] = Spotblock["trafficfillposition"]
                elif Spotblock["blockfillposition"] is None:
                    if len(Spotblock["spots"]) > 1:
                        Spotblock["blockfillposition"] = 0
                break
            elif spot["Description"] == "TRAFFIC LOAD POSITION":
                Spotblock["trafficfillposition"] = len(Spotblock["spots"])-1
            elif spot["Description"] == "Block Fill Position":
                Spotblock["blockfillposition"] = len(Spotblock["spots"])-1
            else:
                if spot["Number-Cut"] and not spot["Length"]:
                    warning("Unresolved spot {} at {}\n", spot["Number-Cut"], Spotblock["Start Time"])
    Hour.append(Spotblock)
    Log.append(Spotblock)

def readlog(file):
    global Hour
    while line:=readline(file):
        description = readcolumn(Columns, line, "Description")
        if description == "TOP OF HOUR":
            time = readcolumn(Columns, line, "Start Time")
            startnewhour(time)
        elif description == "SPOT BLOCK":
            time = readcolumn(Columns, line, "Start Time")
            length = readcolumn(Columns, line, "Length")
            readspotblock(file, readminutes(time), readseconds(length))
        else:
            Log.append(line)
    if time != "24:00:00" and Hour != []:
        warning("Unexpected end of log at {}\n", time)

def startnewhour(time):
    global Log
    global Hour
    Log.append(rendercolumn({"Start Time":time, "Description":"TOP OF HOUR"}))
    usedspots = {}
    for Spotblock in Hour:
        for Spot in Spotblock["spots"]:
            if Spot["Number-Cut"]:
                spotnum = readspotnumcut(Spot["Number-Cut"])[0]
                usedspots[spotnum] = True
    # Skip Mckee foods after sunset
    if time >= "19:00:00":
        usedspots[744] = True
    workinglist = []
    shorts = []
    for spotnum, cuts in Spots.items():
        if spotnum not in usedspots:
            for spot in cuts:
                spot["rotate"] = random.random()
            rotatetable(cuts)
            if cuts[0]["length"] < 25:
                shorts.append({"cuts":cuts,"rotate":random.random()})
            else:
                workinglist.append({"cuts":cuts,"rotate":random.random()})
    rotatetable(workinglist)
    rotatetable(shorts)
    for Spotblock in Hour:
        if Trafficlog:
            starttime = readminutes(Spotblock["Start Time"])
            Trafficlog["file"].write(rendertrafficblock(renderminutes(starttime)))
            Trafficlog["starttime"] = starttime
        fillpos = Spotblock["blockfillposition"] #or len(Spotblock["spots"])
        fill = readseconds(Spotblock["Length"])
        if fill > 0 and fillpos is not None:
            blockcat = ["",""]
            allblockcat = []
            for spot in (s for s in Spotblock["spots"] if s["Number-Cut"]):
                spotnum = readspotnumcut(spot["Number-Cut"])[0]
                if spotnum in Spots and "!" in Spots[spotnum][0]["category"]:
                    allblockcat.append(Spots[spotnum][0]["category"])
            for spot in reversed(Spotblock["spots"][:fillpos]):
                if spot["Number-Cut"]:
                    spotnum = readspotnumcut(spot["Number-Cut"])[0]
                    if spotnum in Spots:
                        blockcat[0] = Spots[spotnum][0]["category"]
                    break
            for spot in Spotblock["spots"][fillpos:]:
                if spot["Number-Cut"]:
                    spotnum = readspotnumcut(spot["Number-Cut"])[0]
                    if spotnum in Spots:
                        blockcat[1] = Spots[spotnum][0]["category"]
                    break
            for overcat in (c for c in set(allblockcat) if allblockcat.count(c) > 1):
                warning("Block at {} contains multiple {} spots.\n", Spotblock["Start Time"], overcat)
            allblockcat = list(set(allblockcat))
            filladjust = 0
            if IsAM:
                #if Spotblock["Start Time"] < "16:00:00":
                if fill > 190:
                    filladjust = -90
                elif fill > 130:
                    filladjust = -60
                if Spotblock["Start Time"] < "06:00:00":
                    filladjust = -fill
            #else:
            #    filladjust = -90
            for spot in Spotblock["spots"]:
                spotlength = spot["Length"]
                if "LEGAL ID" in spot["Description"]:
                    fill -= 10
                elif "LINER A" in spot["Description"] or "LINER B" in spot["Description"]:
                    fill -= 10
                elif findany(spot["Description"], ("[AF]M MORNING",
                                                "[AF]M MIDDAY",
                                                "[AF]M EVENING")) >= 0:
                    fill -= 30
                elif "CBS NEWSBRIEF" in spot["Description"]:
                    fill -= 119
                elif "GOLF UPDATE" in spot["Description"]:
                    fill -= max(readseconds(spotlength), 120)
                elif spotlength:
                    sl = readseconds(spotlength)
                    fill -= sl #readseconds(spotlength)
            if fill < 0:
                warning("Block at {} overfilled by {} seconds.\n", Spotblock["Start Time"], round(-fill,1))
            fill += filladjust
            while fill > 0:
                filllist = shorts if fill < 25 else workinglist
                fillspot = None
                #warning("FILL({}) {}\n",Spotblock["Start Time"],'|'.join(str(cart["cuts"][0]["numcut"][0]) for cart in filllist))
                for i,cart in enumerate(cart["cuts"] for cart in filllist):
                    if cart[0]["numcut"][0] not in usedspots:
                        spot = canfitspot(cart, fill)
                        if spot and spot["category"] not in blockcat + allblockcat:
                            fill -= spot["length"]
                            fillspot = spot
                            blockcat[0] = spot["category"]
                            if "!" in spot["category"]:
                                allblockcat.append(spot["category"])
                            usedspots[spot["numcut"][0]] = True
                            del filllist[i]
                            break
                if fillspot:
                    Spotblock["spots"].insert(fillpos, {
                                                        "Description": fillspot["description"],
                                                        "Length": renderseconds(fillspot["length"]),
                                                        "Start Time": renderminutes(0),
                                                        "Number-Cut": renderspotcut(*fillspot["numcut"])
                                                        })
                    fillpos += 1
                    if Trafficlog:
                        starttime = Trafficlog["starttime"]
                        length = math.floor(fillspot["length"])
                        Trafficlog["file"].write(rendertraffic({
                            "Start Time": renderminutes(starttime),
                            "Number": fillspot["numcut"][0],
                            "Description": fillspot["description"],
                            "Length": length
                            }))
                        Trafficlog["starttime"] = starttime + length
                else:
                    break
            starttime = readminutes(Spotblock["Start Time"])
            for Spot in Spotblock["spots"]:
                Spot["Start Time"] = renderminutes(starttime, True)
                spottime = Spot["Length"]
                if spottime:
                    starttime += readseconds(spottime)
            Spotblock["blockfillposition"] = fillpos
    Hour = []

def main(*argv):
    global Columns, Log, Hour, Spots, IsMonday, IsAM, Trafficlog, LogName
    from os.path import basename,splitext

    Columns = {}
    Log = []
    Hour = []
    Spots = {}

    IsMonday = True
    IsAM = False
    Trafficlog = None

    if len(argv) <= 1:
        return
    elif len(argv) == 2:
        logfile = sys.stdin
        spotfile = open(argv[1], encoding="Windows-1252")
        LogName = None
    else:
        #IsMonday = string.upper(arg[3] or "") == "MONDAY"
        LogName = splitext(basename(argv[1]))[0]
        IsAM = "AM" in LogName.upper()
        logfile = open(argv[1], encoding="Windows-1252")
        spotfile = open(argv[2], encoding="Windows-1252")
        argn = 3
        while argn < len(argv):
            #if arg.upper() == "MONDAY:"
            #    IsMonday = true
            if argv[argn].upper() == "-TRF":
                argn += 1
                trafficdate = argv[argn]
                if match:=re.match(r"(\d\d)(\d\d)(\d\d)(\d\d)", trafficdate):
                    stn,mn,dy,yr = map(int,match.groups())
                    filename = "{:02}{:02}{:02}{:02}.TRF".format(stn,mn,dy,yr)
                    trafficfile = open("Logs\\"+filename, "w", encoding="Windows-1252")
                    trafficfile.write(rendertrafficblock(renderminutes(0),
                                    "{:02} {:02}-{:02}-{:02}".format(stn,mn,dy,yr)))
                    Trafficlog = {"starttime": 0, "file": trafficfile}
            argn += 1
    try:
        Spots = readspotlist(spotfile)
        #for dumpnum,dumpspots in Spots.items():
        #    for dumpcut in dumpspots:
        #        sys.stderr.write(f'''{dumpnum}: "{dumpcut['description']}" {dumpcut['length']} [{dumpcut['category']}]\n''')
        Columns = readheader(logfile)
        readlog(logfile)

        #print(renderheader())
        #for line in Log:
        #    if type(line) is dict:
        #        print(rendercolumn(line))
        #        if "spots" in line:
        #            for entry in line["spots"]:
        #                print(rendercolumn(entry))
        #    elif type(line) is str:
        #        print(line)
    finally:
        if Trafficlog:
            Trafficlog["file"].flush()
            Trafficlog["file"].close()
        if logfile != sys.stdin:
            logfile.close()
        spotfile.close()

if __name__=='__main__':
    import os
    if len(sys.argv) == 3:
        M = int(sys.argv[1])
        D = int(sys.argv[2])
    else:
        M = int(input("Month: "))
        D = int(input("Day: "))
    amtraffic = "01{:02}{:02}23".format(M,D)
    fmtraffic = "02{:02}{:02}23".format(M,D)
    while True:
        main(sys.argv[0], "R:\\Report\\wtonam.txt", "AprAM.txt", "-TRF", amtraffic)
        main(sys.argv[0], "R:\\Report\\wtonfm.txt", "AprFM.txt", "-TRF", fmtraffic)
        if Warnings > 0:
            try:
                response = input("Continue? (Yes)") or "Y"
            except KeyboardInterrupt:
                response = "N"
            if response[0].upper() == "R":
                continue
            elif response[0].upper() != "Y":
                break
        if os.path.exists("R:\\Traffic\\WTON-AM\\"+amtraffic+".TRF"):
            try:
                os.rename("R:\\Traffic\\WTON-AM\\"+amtraffic+".TRF", "R:\\Traffic\\WTON-AM\\"+amtraffic+"~.TRF")
            except FileExistsError:
                pass
        destfile = open("R:\\Traffic\\WTON-AM\\"+amtraffic+".TRF", "w", encoding="Windows-1252")
        try:
            trafficfile = open("Logs\\"+amtraffic+".TRF", "r", encoding="Windows-1252")
            for line in trafficfile:
                if findany(line, ["000(509|541|552|589|603|605|777|780|789|864|868|035|686|921)"]) < 0:
                    destfile.write(line)
            trafficfile.close()
        except:
            destfile.close()
            os.remove("R:\\Traffic\\WTON-AM\\"+amtraffic+".TRF")
            raise
        destfile.flush()
        destfile.close()
        if os.path.exists("R:\\Traffic\\WTON-FM\\"+fmtraffic+".TRF"):
            try:
                os.rename("R:\\Traffic\\WTON-FM\\"+fmtraffic+".TRF", "R:\\Traffic\\WTON-FM\\"+fmtraffic+"~.TRF")
            except FileExistsError:
                pass
        destfile = open("R:\\Traffic\\WTON-FM\\"+fmtraffic+".TRF", "w", encoding="Windows-1252")
        try:
            trafficfile = open("Logs\\"+fmtraffic+".TRF", "r", encoding="Windows-1252")
            destfile.write(trafficfile.read())
            trafficfile.close()
        except:
            destfile.close()
            os.remove("R:\\Traffic\\WTON-FM\\"+fmtraffic+".TRF")
            raise
        destfile.flush()
        destfile.close()
        break
