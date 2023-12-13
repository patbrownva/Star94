import re
from bs4 import BeautifulSoup

from loguru import logger

from flexget import plugin
from flexget.entry import Entry
from flexget.event import event
from flexget.utils.template import RenderError, render_from_entry
from flexget.config_schema import parse_interval

logger = logger.bind(name='premierenetworks')

API = "https://api.premiereaffidavits.com/"
#URL = "https://www.premiereaffidavits.com/"
#WService = URL+"scripts/cgiip.exe/WService=webprime/"
#MP2ZIPS = URL+"mp2zips/"
#DOWNLOADFILE_RE = re.compile(r'\bFILE=([^&]+)')
#TABLEHEADING_RE = re.compile(r'^\s*Show:\s*(.+?)\s+Week:\s*(.+?)\s*$')

#ROWID_RE = re.compile(r'window\.location\.href="[\w.]*\?rowid=(0x[0-9A-Fa-f]+)"')
#def get_table(html):
#    table = BeautifulSoup(html, 'html5lib').find('table', class_='table')
#    if not table:
#        raise ValueError("Couldn't find table.")
#    headers = tuple(td.get_text().strip() for td in table.find_all('th'))
#    def _get_row(row):
#        data = tuple(td.get_text().strip() for td in row.find_all('td'))
#        return dict(zip(headers, data)) if headers else data
#    return [_get_row(row) for row in table.find_all('tr') if row.find('td')]

##class PremiereNetworks:
##
##    session = None
##    row_id = None
##
##    def __init__(self, session):
##        self.session = session
##
##    def login(self, name, password):
##        response = self.session.post(WService+"login.html",
##                                     data={'B1':'Submit', 'login':name, 'password':name})
##        response.raise_for_status()
##        if m := ROWID_RE.search(response.text):
##            self.row_id = m.group(1)
##            return True
##        return False
##
##    def logout(self):
##        if self.row_id:
##            self.session.get(WService+"login.html", params={'rowid':self.row_id})
##        self.row_id = None
##
##    def shows(self):
##        response = self.session.get(WService+"shows.html", params={'rowid':self.row_id})
##        response.raise_for_status()
##        return get_table(response.content)
##
##    # date format is %m/%d/%y
##    def affidavits(self, name, start_date=None, start_week=None):
##        response = self.session.get(WService+"schedule.html", params={'rowid':self.row_id})
##        response.raise_for_status()
##        if isinstance(name, str):
##            if not exp:
##                raise ValueError("name cannot be empty")
##            name = re.compile('^'+re.escape(name)+'$')
##        if not isinstance(name, re.Pattern):
##            try:
##                exp = '|'.join(map(re.escape, name))
##                if not exp:
##                    raise ValueError("name cannot be empty")
##                name = re.compile('^('+exp+')$')
##            except TypeError:
##                raise TypeError("name must be one or more strings, or compiled pattern")
##        if start_date:
##            def _filter(row):
##                return name.match(row['Show Title']) and row['Week Of Date'] == start_date
##        elif start_week:
##            def _filter(row):
##                return name.match(row['Show Title']) and row['Week'] == start_week
##        else:
##            def _filter(row):
##                return name.match(row['Show Title']) is not None
##        return [row['Spot Detail'] for row in get_table(response.content) if _filter(row)]
##
##    def schedule(self, affidavit_num):
##        response = self.session.get(WService+"schedspots.html",
##                                    params={'rowid':self.row_id, 'AFFIDAVITNO':affidavit_num})
##        response.raise_for_status()
##        return get_table(response.content)
##
##    def download(self, affidavit_num):
##        response = self.session.get(WService+"schedspots.html",
##                                    params={'rowid':self.row_id, 'AFFIDAVITNO':affidavit_num})
##        response.raise_for_status()
##        html = BeautifulSoup(response.text, 'html5lib')
##        link = html.find('a', attrs={'href':DOWNLOADFILE_RE})
##        href = DOWNLOADFILE_RE.search(link['href']).group(1) if link else None
##        try:
##            heading = html.find('h1').find_next('table').text
##            title_match = TABLEHEADING_RE.match(heading)
##            if title_match:
##                title = title_match.groups()
##            else:
##                title = (heading.strip(), "")
##        except (AttributeError,TypeError):
##            title = (href.replace(".zip",""), "")
##        return href, title

class PremiereNetworks:

    session = None
    affiliate_id = None

    def __init__(self, session):
        self.session = session

    def login(self, name, password):
        response = self.session.post(API+"token",
                                     json={'userName':name, 'password':name})
        response.raise_for_status()
        token = response.json()
        if 'access_token' in token:
            self.session.headers['Authorization'] = token['token_type'].title() + " " + token['access_token']
            self.affiliate_id = token['affiliateId']
            return True
        return False

    def logout(self):
        self.affiliate_id = None

    def shows(self):
        response = self.session.post(API+"show",
                                    json={'affiliateId':self.affiliate_id})
        response.raise_for_status()
        return response.json()

    # date format is %Y-%m-%d
    def affidavits(self, name, start_date=None):
        response = self.session.post(API+"affidavit", json={'affiliateId':self.affiliate_id})
        response.raise_for_status()
        if isinstance(name, str):
            if not exp:
                raise ValueError("name cannot be empty")
            name = re.compile('^'+re.escape(name)+'$')
        if not isinstance(name, re.Pattern):
            try:
                exp = '|'.join(map(re.escape, name))
                if not exp:
                    raise ValueError("name cannot be empty")
                name = re.compile('^('+exp+')$')
            except TypeError:
                raise TypeError("name must be one or more strings, or compiled pattern")
        afflist = [aff for aff in response.json() if name.match(aff['show'])]
        if start_date:
            response = self.session.post(API+"broadcastweek", json={'broadcast':start_date})
            broadcastweek = response.json()
            if 'errors' not in broadcastweek:
                broadcastweek = broadcastweek[0]
                afflist = [aff for aff in afflist if aff['week'] == broadcastweek['week'] and aff['year'] == broadcastweek['year']]
        return afflist

    def schedule(self, name, start_date=None):
        response = self.session.post(API+"schedule", json={'affiliateId':self.affiliate_id})
        response.raise_for_status()
        if isinstance(name, str):
            if not exp:
                raise ValueError("name cannot be empty")
            name = re.compile('^'+re.escape(name)+'$')
        if not isinstance(name, re.Pattern):
            try:
                exp = '|'.join(map(re.escape, name))
                if not exp:
                    raise ValueError("name cannot be empty")
                name = re.compile('^('+exp+')$')
            except TypeError:
                raise TypeError("name must be one or more strings, or compiled pattern")
        sched = [row for row in response.json() if name.match(row['show'])]
        if start_date:
            response = self.session.post(API+"broadcastweek", json={'broadcast':start_date})
            broadcastweek = response.json()
            if 'errors' not in broadcastweek:
                broadcastweek = broadcastweek[0]
                sched = [row for row in afflist if row['week'] == broadcastweek['week'] and row['year'] == broadcastweek['year']]
        return sched


class InputPremiere:
    """
    Get audio download links from Premiere Networks.
    """

    schema = {
        'type': 'object',
        'properties': {
            'username': {'type':'string'},
            'password': {'type':'string'},
            'named': {'type':'array', 'items':{'type':'string'}},
        },
        'required': ['username','password','named'],
        'additionalProperties': False,
    }

    @plugin.internet(logger)
    def on_task_input(self, task, config):
        PN = PremiereNetworks(task.requests)
        if PN.login(config['username'], config['password']):
            try:
                show_list = PN.schedule(config['named'])
                return [Entry({
                               'url': show['zipFileUrl'],
                               'title': show['zipFileName'],
                               'series_name': show['show'],
                               'series_date': show['broadcastWeek']}) for show in show_list]
            finally:
                PN.logout()

@event('plugin.register')
def register_plugin():
    plugin.register(InputPremiere, 'premierenetworks', api_ver=2)
