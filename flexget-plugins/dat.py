from datetime import datetime,timedelta
import io
import os

from loguru import logger

from flexget import plugin
from flexget.event import event
from flexget.utils.template import RenderError, render_from_entry
from flexget.config_schema import parse_interval

def parse_datetime_interval(time_string):
    """Parse a date and (optional) time string into a :class:`datetime.datetime` object."""
    try:
        if 'weekday' in time_string.lower():
            td = parse_interval(time_string.lower().replace('weekday','day'))
            date = datetime.today() + td
            if date.weekday() > 4:
                date += timedelta(days= 7-date.weekday())
            return date
        else:
            td = parse_interval(time_string)
            return datetime.today() + td
    except ValueError:
        pass

    date_formats = ['%m/%d/%Y', '%m/%d/%y', '%d-%m-%Y', '%Y/%m/%d', '%Y-%m-%d']
    time_formats = ['%I:%M %p', '%H:%M', '%H:%M:%S']
    for df in date_formats:
        for tf in time_formats:
            try:
                return datetime.strptime(time_string, df+' '+tf)
            except ValueError:
                continue
            try:
                return datetime.strptime(time_string, tf+' '+df)
            except ValueError:
                continue
    raise ValueError('invalid datetime `%s`' % time_string)


logger = logger.bind(name='dat')


START_DATE = datetime(2001,1,1)
END_DATE = datetime(2100,1,1,23,59,59)

class DATEntry:
    spot_num = 0
    cut_num = 0
    spot_type = 'SPOT'
    title = ''
    co_op = ''
    talent = ''
    comment = ''
    cue = ''
    start_date = START_DATE
    end_date = END_DATE
    archive_date = END_DATE
    erase_date = END_DATE
    recorded_date = datetime.today()
    filename = ''
    length = timedelta(0)

    def __init__(self, spot, cut):
        self.spot_num = int(spot)
        self.cut_num = int(cut)

    def output(self):
        lines = []
        current_line = []
        def add_text(text):
            current_line.append(text.encode('Windows-1252'))
        def push_line(text):
            add_text(text)
            lines.append(b" ".join(current_line) + b"\r\n")
            current_line.clear()
        push_line('"VERSION"')
        push_line('"080006"')
        push_line('"SPOT"')
        add_text(f'"{self.title}"')
        add_text(f'"{self.co_op}"')
        add_text(f'"{self.talent}"')
        add_text(f'{self.start_date:%m/%d/%Y}')
        add_text(f'{self.end_date:%m/%d/%Y}')
        add_text(f'"{self.start_date:%H%M%S}"')
        add_text(f'"{self.end_date:%H%M%S}"')
        add_text(f'{self.archive_date:%m/%d/%Y}')
        add_text(f'{self.spot_num}{self.cut_num:03}')
        add_text(f'{self.spot_num}')
        add_text(f'{self.recorded_date:%m/%d/%Y "%H:%M:%S"}')
        add_text(f'0 22 {self.cut_num}')
        add_text(f'"{self.filename}"')
        add_text(f'"{(START_DATE+self.length):%H%M%S}"')
        add_text('"000"')
        add_text(f'"%ANO %B          %C{self.cue:30}%DN"')
        add_text(f'"{self.comment}"')
        add_text('""')
        add_text(f'"{self.comment}"')
        push_line(f'"{self.length.microseconds//10000}"')
        add_text('[EXT_1]')
        add_text(f'{self.archive_date:%H:%M:%S}')
        add_text(f'{self.erase_date:%m/%d/%Y %H:%M:%S}')
        add_text(f'0 -1 ~ {self.length.microseconds//1000}')
        push_line('0 000 0 0')
        push_line('[EXT_2]   0 -1 -1 -1 -1 0 0 ""')
        add_text(f'"{self.spot_type}"')
        push_line('"" 0' if self.spot_type=='SHOWS' else '')

        return b''.join(lines)

    @classmethod
    def load(cls, data):
        self = cls.__new__(cls)
        lines = iter(data.split(b'\r\n'))
        current_line = b''
        pos = 0
        def get_line():
            nonlocal pos, current_line, lines
            current_line = next(lines).decode('Windows-1252')
            pos = 0
        def get_text():
            nonlocal pos, current_line
            if pos >= len(current_line):
                return ''
            if current_line[pos] == '"':
                pos += 1
                quo = pos
                while quo < len(current_line):
                    if current_line[quo] == '"':
                        if current_line[quo+1:quo+2] == '"':
                            quo += 2
                            continue
                        break
                    quo += 1
                text = current_line[pos:quo].replace('""', '"')
                pos = quo + 1
                while pos < len(current_line):
                    if current_line[pos] != ' ':
                        break
                    pos += 1
                return text
            else:
                spa = current_line.find(' ', pos)
                text = current_line[pos:spa]
                pos = spa + 1
                while pos < len(current_line):
                    if current_line[pos] != ' ':
                        break
                    pos += 1
                return text
        def expect(text):
            if text != get_text():
                raise ValueError("Bad DAT")
        get_line()
        expect('VERSION')
        get_line()
        expect('080006')
        get_line()
        expect('SPOT')
        get_line()
        self.title = get_text()
        self.co_op = get_text()
        self.talent = get_text()
        start_date = get_text()
        end_date = get_text()
        start_time = get_text()
        end_time = get_text()
        self.start_time = datetime.strptime(start_date+' '+start_time, '%m/%d/%Y %H%M%S')
        self.end_time = datetime.strptime(end_date+' '+end_time, '%m/%d/%Y %H%M%S')
        arc_date = get_text()
        arc_time = None
        spotcut = get_text() # f'{self.spot_num}{self.cut_num:03}'
        self.spot_num = int(get_text())
        rec_date = get_text()
        rec_time = get_text()
        self.recorded_date = datetime.strptime(rec_date+' '+rec_time, '%m/%d/%Y %H:%M:%S')
        get_text() # expect('0')
        get_text() # expect('22')
        self.cut_num = int(get_text())
        self.filename = get_text()
        length_time = datetime.strptime(f'{START_DATE:%m/%d/%y} '+get_text(), '%m/%d/%y %H%M%S')
        self.length = length_time - START_DATE
        get_text() # expect('000')
        cue_text = get_text()
        get_text()
        get_text()
        self.comment = get_text()
        ms_text = int(get_text()) * 10000
        get_line()
        spot_type = get_text()
        if spot_type == '[EXT_1]':
            arc_time = get_text()
            erase_date = get_text()
            erase_time = get_text()
            self.erase_date = datetime.strptime(erase_date+' '+erase_time, '%m/%d/%Y %H:%M:%S')
            get_text() # '0'
            get_text() # '-1'
            get_text() # '~'
            ms_text = int(get_text()) * 1000
            get_line() # skip '0 000 0 0'
            spot_type = get_text()
        if spot_type == '[EXT_2]':
            get_line()
            spot_type = get_text()
        logger.debug(spot_type)
        self.spot_type = spot_type
        logger.debug(self.spot_type)
        #if spot_type == 'SHOWS':
        #    get_line() # "" 0
        self.archive_date = datetime.strptime(arc_date+' '+arc_time, '%m/%d/%Y %H:%M:%S')
        self.length += timedelta(microseconds=ms_text)
        return self

class OutputDAT:
    """
    Write DAT for each succeeded (downloaded) entry.

    """

    schema = {
        'type': 'object',
        'properties': {
            'title': {'type': 'string'},
            'spot': {'type': 'integer'},
            'cut': {'type': 'integer'},
            'type': {'type': 'string'},
            'enddate': {'type': 'string'},
            'template': {'type': 'string'},
        },
        #'required': ['spot','cut'],
        'additionalProperties': False,
    }

    def prepare_config(self, config):
        config.setdefault('type', 'SPOT')
        config.setdefault('title', '{{title}}')
        return config

    @plugin.priority(120)
    def on_task_output(self, task, config):
        #config = self.prepare_config(config)

        for entry in task.accepted:
            template = None
            if entry.get('dat_template') or config.get('template'):
                with io.open(entry.get('dat_template', config.get('template')), 'rb') as file:
                    template = file.read()
            if template:
                try:
                    dat = DATEntry.load(template)
                except ValueError:
                    logger.verbose("Bad DAT.")
                    continue
                if entry.get('dat_spot') or config.get('spot'):
                    dat.spot_num = entry.get('dat_spot',config.get('spot'))
                if entry.get('dat_cut') or config.get('cut'):
                    dat.cut_num = entry.get('dat_cut',config.get('cut'))
            else:
                config = self.prepare_config(config)
                dat = DATEntry(entry.get('dat_spot',config.get('spot')), entry.get('dat_cut',config.get('cut')))

            dat.filename = entry.get('filename', '')
            dat.title = entry['title']
            dat_title = entry.get('dat_title',config.get('title'))
            if dat_title:
                try:
                    dat.title = entry.render(dat_title)
                except RenderError as e:
                    logger.error(
                        'Error rendering jinja title for `{}` falling back to entry title: {}',
                        entry['title'],
                        e,
                    )
                    dat.title = entry['title']
            if entry.get('dat_type') or config.get('type'):
                dat.spot_type = entry.get('dat_type',config.get('type'))

            end_date = entry.get('dat_enddate',entry.get('enddate',config.get('enddate')))
            if end_date:
                dat.end_date = parse_datetime_interval(end_date)

            filename = os.path.splitext(entry['location'])[0] + '.DAT'

            logger.verbose('Saving DAT for {}', dat.title)
            # don't run with --test
            if task.options.test:
                logger.info('Would write DAT file {}.', filename)
                return

            with io.open(filename, 'wb') as file:
                file.write(dat.output())


@event('plugin.register')
def register_plugin():
    plugin.register(OutputDAT, 'dat', api_ver=2)
