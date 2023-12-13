from bs4 import BeautifulSoup
from datetime import date,time,datetime,timedelta
import io
import os
import re
import subprocess
import yaml
from functools import reduce

from loguru import logger

from flexget import plugin
from flexget.entry import Entry
from flexget.event import event
from flexget.utils.template import RenderError, render_from_entry
from flexget.config_schema import parse_interval

from .dat import DATEntry, parse_datetime_interval

FFMPEG_PATH = os.path.join(os.path.expanduser('~'),'flexget','ffmpeg.exe')
SILENCE_START = re.compile(r"] silence_start: ([0-9.]+)", re.M)
SILENCE_END = re.compile(r"] silence_end: ([0-9.]+)", re.M)
DURATION = re.compile(r"^ *Duration: ([0-9:.]+)", re.M)

TITLE_RE = re.compile(r"<.*?(?::(.+))?>")
KILL_DATE = re.compile(r"KILL DATE[:\s]+(\d+)/(\d+)/(\d+)")
INTERVAL_RE = re.compile(r"(?:(\d+[-/]\d+[-/]\d+[-/]) ?- ?)?(.*)")

logger = logger.bind(name='espn')

def parse_duration(duration_string):
    return reduce(lambda a,b: a*60+b, map(float, duration_string.split(':')), 0)

def parse_date_interval(date_string):
    """Parse a datestring into a :class:`datetime.date` object."""
    date_formats = ['%d/%m/%Y', '%d/%m/%y', '%d-%m-%Y', '%Y/%m/%d', '%Y-%m-%d']
    date_match = INTERVAL_RE.match(date_string).groups()
    def _parse_date(ds):
        for df in date_formats:
            try:
                return datetime.strptime(ds, df).date()
            except ValueError:
                continue
        raise ValueError('invalid date `%s`' % ds)
    date1 = date.today() if date_match[1].upper() == 'TODAY' else _parse_date(date_match[1])
    if date_match[0]:
        date2 = date1
        date1 = date.today() if date_match[0].upper() == 'TODAY' else _parse_date(date_match[0])
    else:
        date2 = None
    return date1,date2

def find_by_class(content, element, class_):
    return BeautifulSoup(content, 'html5lib').find_all(element, class_=class_)

def execute_cmd(*args):
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    response = proc.stdout.read()
    proc.stdout.close()
    return proc.wait(), response

class ESPNAudio:
    url = 'https://espnaudio.espn.com/'
    username = 'LOGIN-REMOVED'
    password = 'PASSWORD-REMOVED'

    def __init__(self, session):
        self.session = session
        self.logged_in = False

    def login(self):
        response = self.session.post(self.url+'login.php', data={'username':self.username,'password':self.password})
        for div in find_by_class(response.content, 'div', 'statusbar'):
            if 'logged in' in div.get_text():
                self.logged_in = True
                break
        else:
            self.logged_in = False
        return self.logged_in

    def index(self, q='', d1='', d2='', cutnum='', cutgroup='All'):
        tablekeys = ('cutnum', 'title', 'length', 'cue', 'description', 'artist', 'billboard', 'sourcedb', 'cutgroup', 'date', 'IGNORE')
        def _get_row(row):
            fields = dict(zip(tablekeys, (td.get_text() for td in row.find_all('td'))))
            del fields['IGNORE']
            fields['url'] = self.url+"listen.php?download=mp2&serial="+fields.get('sourcedb','')+"-"+fields.get('cutnum','')
            fields['cutnum'] = int(fields['cutnum']) if 'cutnum' in fields else 0
            if 'title' not in fields:
                fields['title'] = str(fields['cutnum'])
            if 'billboard' in fields and (kill := KILL_DATE.match(fields['billboard'])):
                m,d,y = map(int,kill.groups())
                if y < 2000:
                    y += 2000
                fields['enddate'] = f"{y}-{m}-{d} 23:59:59"
            return fields
        keys = ['d=1', 'cutgroup='+cutgroup]
        if q:
            keys.append('q='+q)
        if d1:
            keys.append('d1='+d1)
        if d2:
            keys.append('d2='+d2)
        if cutnum:
            keys.append('cutnum='+cutnum)
        response = self.session.get(self.url+'index.php?'+'&'.join(keys))
        return [_get_row(row) for row in find_by_class(response.content, 'tr', re.compile('shade[12]'))]

class InputESPN:
    """
    Parse audio from ESPN external retrieval system.
    """

    schema = {
        'type': 'object',
        'properties': {
            'text': {'type':'string'},
            'group': {'type':'string'},
            'date': {'type':'string'},
            'manual': {'type':'string'},
        },
        'additionalProperties': False
    }

    @plugin.internet(logger)
    def on_task_input(self, task, config):
        espn = ESPNAudio(task.requests)
        if not espn.login():
            raise plugin.PluginError('Could not login to ERS')
        if config.get('date'):
            date1,date2 = parse_date_interval(config['date'])
            date1 = date1.strftime("%m/%d/%Y") if date1 else ''
            date2 = date2.strftime("%m/%d/%Y") if date2 else ''
        else:
            date1,date2 = '',''
        index = espn.index(config.get('text'), date1, date2, cutgroup=config.get('group'))
        try:
            if config.get('manual'):
                seen_cuts = set((e['cutnum'] for e in index))
                for line in io.open(config['manual'], 'r', encoding='utf-8'):
                    try:
                        cutnum = int(line)
                        if cutnum not in seen_cuts:
                            manual = espn.index(cutnum=str(cutnum), cutgroup='')
                            index.extend(manual)
                            seen_cuts.add(cutnum)
                    except ValueError:
                        pass
        except OSError:
            pass
        return [Entry(e) for e in index]


class OutputESPN:
    """
    Import audio downloaded from ESPN.
    """

    schema = {
        'type': 'object',
        'properties': {
            'path': {'type':'string'},
            'spot': {'type':'integer'},
            'map': {'type':'string'}
        },
        'required': ['path', 'spot', 'map'],
        'additionalProperties': False
    }

    def on_task_filter(self, task, config):
        try:
            cut_map = yaml.safe_load(io.open(config['map'], 'r', encoding='utf-8').read())
        except:
            logger.debug('Could not read mapping file.')
            return

        for entry in task.entries:
            cut_num = entry.get('cutnum')
            if not cut_num:
                logger.verbose('Entry does not have a cut number.')
            elif cut_num not in cut_map:
                #logger.debug('Skipping entry with cut number {}.', cut_num)
                entry['dat_spot'] = entry['cutnum'] // 100 + 990000
                entry['dat_cut'] = entry['cutnum'] % 100
                entry.accept()
            elif cut_map[cut_num] == 'reject':
                entry.reject('Explicitly rejected by cut map.')
            else:
                if dat_cut := cut_map[cut_num].get('cut'):
                    entry['dat_cut'] = dat_cut
                else:
                    entry['dat_cut'] = entry['cutnum'] % 100
                if 'spot' in cut_map[cut_num]:
                    entry['dat_spot'] = cut_map[cut_num]['spot']
                else:
                    entry['dat_spot'] = config['spot']
                if 'enddate' in cut_map[cut_num]:
                    entry['enddate'] = cut_map[cut_num]['enddate']
                if 'title' in cut_map[cut_num]:
                    entry['dat_title'] = cut_map[cut_num]['title']
                try:
                    if 'length' in cut_map[cut_num]:
                        entry['cut_length'] = float(cut_map[cut_num]['length'])
                except ValueError:
                    logger.debug('Parse error, length not a number.')
                entry.accept()

    @plugin.priority(120)
    def on_task_output(self, task, config):
        for entry in task.accepted:
            dat = DATEntry(entry['dat_spot'], entry['dat_cut'])
            dat.title = TITLE_RE.sub('\\1', entry.get('dat_title',entry['title']))+f" ({entry['cutnum']})"
            dat.spot_type = 'FILL'
            try:
                if entry.get('enddate'):
                    dat.end_date = parse_datetime_interval(entry['enddate'])
                    dat.end_date = datetime.combine(dat.end_date, time(23,59,59))
            except ValueError:
                dat.end_date = dat.archive_date

            filename = f"{dat.spot_num:06}{dat.cut_num:02}"
            datfile = os.path.join(config['path'],filename+'.DAT')
            outputfile = os.path.join(config['path'],filename+'.wav')
            dat.filename = filename+'.wav'

            if not task.options.test:
                cut_length, cut_offset = self.get_cut_length(entry['location'])
                if cut_length is None:
                    entry.fail('external command failed')
                    return
                if cut_length < 1 and (title_length := re.search(r"(\d*):(\d+)", entry['title'])):
                    try:
                        cut_length = float(title_length.group(1) or 0) * 60 + float(title_length.group(2))
                    except ValueError:
                        cut_length = -1
                if entry.get('cut_length') and (cut_length < 1 or cut_length > entry['cut_length']):
                    cut_length = entry['cut_length']
                if cut_length > 0:
                    dat.length = timedelta(seconds=cut_length)
                    if not self.copy_audio(entry['location'], outputfile, cut_length, cut_offset):
                        entry.fail('external command failed')
                        return

            logger.verbose('Saving DAT for {}', dat.title)
            # don't run with --test
            if task.options.test:
                logger.info('Would write DAT file {}.', datfile)
            else:
                with open(datfile, 'wb') as file:
                    file.write(dat.output())

    def get_cut_length(self, filename):
        result, response = execute_cmd(FFMPEG_PATH,
                                       "-hide_banner",
                                       "-i", filename,
                                       "-af","silencedetect=-30dB:d=0.76",
                                       "-f","null","-"
                                       )
        if result != 0:
            logger.debug('Commend execution failed, response: {}', response.rstrip())
            return None, None
        try:
            silence_splits = SILENCE_START.search(response)
            seconds = float(silence_splits.group(1))
            if seconds >= 1:
                return seconds, 0.0
            offset = float(SILENCE_END.search(response).group(1))
            seconds = SILENCE_START.search(response, silence_splits.end()).group(1)
            return float(seconds)-offset, offset
        except AttributeError:
            pass
        except IndexError:
            pass
        except ValueError:
            logger.debug('Parse error, {} not a number.', seconds)
            return None
        try:
            seconds = DURATION.search(response).group(1)
            return parse_duration(seconds), 0.0
        except AttributeError:
            pass
        except IndexError:
            pass
        except ValueError:
            logger.debug('Parse error, {} not a number.', seconds)
            return None, None
        return -1.0,0.0


    def copy_audio(self, location, filename, length, offset=0.0):
        result, response = execute_cmd(FFMPEG_PATH,
                                       "-hide_banner",
                                       "-y",
                                       "-i", location,
                                       "-c","copy",
                                       "-t",f"{length:.4}s",
                                       "-ss",f"{offset:.4}s",
                                       filename
                                       )
        if result != 0:
            logger.debug('Command execution failed, response: {}', response.rstrip())
            return False
        return True


@event('plugin.register')
def register_plugin():
    plugin.register(InputESPN, 'espn', api_ver=2)
    plugin.register(OutputESPN, 'espnaudio', api_ver=2)
