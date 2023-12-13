from bs4 import BeautifulSoup
from email.header import decode_header
from urllib.parse import urlsplit, quote as urlquote, unquote as urlunquote
from base64 import b64decode as base64_decode
from quopri import decodestring as quopri_decode
from hashlib import md5 as hash_function
import mimetypes
import imaplib
import re
import io
import os
import tempfile
import shutil
import socket
import sys

class ImapNotLoggedInError(Exception):
    pass

class ImapBadResponse(Exception):
    pass

class ImapNoMessage(Exception):
    pass

imap_errors = (imaplib.IMAP4.error, imaplib.IMAP4_SSL.error, ImapNotLoggedInError, ImapNoMessage)

from loguru import logger

from flexget import plugin
from flexget.entry import Entry
from flexget.event import event
from flexget.utils.pathscrub import pathscrub
from flexget.utils.template import RenderError, render_from_entry
from flexget.config_schema import parse_interval

logger = logger.bind(name='imap')

def import_utf7():
    """
    Encode and decode UTF-7 string, as described in the RFC 3501
    There are variations, specific to IMAP4rev1, therefore the built-in python UTF-7 codec can't be used.
    The main difference is the shift character, used to switch from ASCII to base64 encoding context.
    This is "&" in that modified UTF-7 convention, since "+" is considered as mainly used in mailbox names.
    Full description in the RFC 3501, section 5.1.3.
    """

    import binascii


    # ENCODING
    # --------
    def _modified_base64(s):
        return binascii.b2a_base64(s.encode('utf-16be')).rstrip(b'\n=').replace(b'/', b',')


    def _do_b64(_in, r):
        if _in:
            r.append(b'&' + _modified_base64(''.join(_in)) + b'-')
        del _in[:]


    def encode(s: str) -> bytes:
        res = []
        _in = []
        for c in s:
            ord_c = ord(c)
            if 0x20 <= ord_c <= 0x25 or 0x27 <= ord_c <= 0x7e:
                _do_b64(_in, res)
                res.append(c.encode())
            elif c == '&':
                _do_b64(_in, res)
                res.append(b'&-')
            else:
                _in.append(c)
        _do_b64(_in, res)
        return b''.join(res)


    # DECODING
    # --------
    def _modified_unbase64(s):
        return binascii.a2b_base64(s.replace(b',', b'/') + b'===').decode('utf-16be')


    def decode(s: bytes) -> str:
        res = []
        decode_arr = bytearray()
        for c in s:
            if c == ord('&') and not decode_arr:
                decode_arr.append(ord('&'))
            elif c == ord('-') and decode_arr:
                if len(decode_arr) == 1:
                    res.append('&')
                else:
                    res.append(_modified_unbase64(decode_arr[1:]))
                decode_arr = bytearray()
            elif decode_arr:
                decode_arr.append(c)
            else:
                res.append(chr(c))
        if decode_arr:
            res.append(_modified_unbase64(decode_arr[1:]))
        return ''.join(res)

    return [encode, decode]

utf7_encode,utf7_decode = import_utf7()

def import_bodystructure():
    class ParseError(Exception):
        pass

    def ident(arg):
        return arg

    def nil(arg):
        return None

    STRINGESCAPE_RE = re.compile(r'\\([\\"])')
    def parse_string(arg):
        return STRINGESCAPE_RE.sub('\\1', arg)

    TOKEN_PATTERNS = (
        ('(', re.compile(r'\(\s*', re.MULTILINE), nil),
        (')', re.compile(r'\)\s*', re.MULTILINE), nil),
        ('STRING', re.compile(r'"((?:\\[\\"]|[^"])*)"\s*', re.MULTILINE), parse_string),
        ('NUMBER', re.compile(r'([0-9]+)\s*', re.MULTILINE), int),
        ('NIL', re.compile(r'NIL\s*', re.MULTILINE), nil),
    )
    BODYSTRUCTURE_RE = re.compile(r'\bBODY(?:STRUCTURE)?\s+\(\s*', re.MULTILINE)

    def next_token(data, position):
        for token,pattern,func in TOKEN_PATTERNS:
            match = pattern.match(data, position)
            if match:
                value = match.group(1) if match.lastindex else None
                return token, func(value), match.end()
        raise ParseError("Invalid character at position {}.".format(position))

    def parse_list(data, position):
        nested_list = []
        current_list = []
        while position < len(data):
            token,value,position = next_token(data, position)
            if token == '(':
                nested_list.append(current_list)
                current_list = []
            elif token == ')':
                if nested_list:
                    nested_list[-1].append(tuple(current_list))
                    current_list = nested_list.pop()
                else:
                    return tuple(current_list), position
            else:
                current_list.append(value)
        raise ParseError("Unexpected end of data.")

    def parse_pairs(data):
        try:
            result = {}
            multi = set()
            for name,value in zip(data[::2],data[1::2]):
                name = name.lower()
                if value is not None:
                    if name in result:
                        result[name] = (result[name] if name in multi else (result[name],)) + (value,)
                        multi.add(name)
                    else:
                        result[name] = value
            return result
        except (TypeError, AttributeError):
            return {}

    def has_index(L, ix):
        return len(L) > ix and L[ix] is not None

    def check_index(L, ix, typ):
        return len(L) > ix and isinstance(L[ix], typ)

    def parse_section(data, is_multipart):
        section = {}
        if is_multipart:
            if not check_index(data, 0, str):
                raise ValueError("Invalid section.")
            section['content-type'] = "multipart/" + data[0].lower()
            section['attributes'] = parse_pairs(data[1])
            if check_index(data, 2, tuple):
                section['content-disposition'] = (data[2][0].lower(), parse_pairs(data[2][1]))
            elif check_index(data, 2, str):
                section['content-disposition'] = (data[2].lower(),)
            if has_index(data, 3):
                section['content-language'] = data[3]
            if has_index(data, 4):
                section['content-location'] = data[4]
            if len(data) > 5:
                section['extension-data'] = data[5:]
        else:
            if not (check_index(data, 0, str) and check_index(data, 1, str)):
                raise ValueError("Invalid section.")
            section['content-type'] = "/".join(data[0:2]).lower()
            section['attributes'] = parse_pairs(data[2])
            if has_index(data, 3):
                section['content-id'] = data[3]
            if has_index(data, 4):
                section['content-description'] = data[4]
            if check_index(data, 5, str):
                section['content-encoding'] = data[5].lower()
            if has_index(data, 6):
                section['content-length'] = data[6]
            if section['content-type'] in ("text/plain", "text/html"):
                section['content-lines'] = data[7]
                ext_index = 8
            elif section['content-type'] == "message/rfc822":
                section['content-envelope'] = data[7]
                section['content-structure'] = data[8]
                section['content-lines'] = data[9]
                ext_index = 10
            else:
                ext_index = 7
            if has_index(data, ext_index):
                section['content-md5'] = data[ext_index]
            if check_index(data, ext_index+1, tuple):
                section['content-disposition'] = (data[ext_index+1][0].lower(), parse_pairs(data[ext_index+1][1]))
            elif check_index(data, ext_index+1, str):
                section['content-disposition'] = (data[ext_index+1].lower(),)
            if has_index(data, ext_index+2):
                section['content-language'] = data[ext_index+2]
            if has_index(data, ext_index+3):
                section['content-location'] = data[ext_index+3]
            if len(data) > ext_index+4:
                section['extension-data'] = data[ext_index+4:]
        return section

    def parse_bodystructure(data, position=0):
        bs_start = BODYSTRUCTURE_RE.search(data)
        if not bs_start:
            raise ParseError("BODYSTRUCTURE not found in data.")
        #sections = []
        section_table = {'':None}
        position = bs_start.end()
        section_counter = [1]
        current_section = []
        is_multipart = False
        while position < len(data):
            token,value,position = next_token(data, position)
            if token == '(':
                if not current_section:
                    section_table['.'.join(map(str,section_counter))] = None
                    section_counter.append(1)
                    is_multipart = False
                else:
                    value,position = parse_list(data, position)
                    current_section.append(value)
            elif token == ')':
                section_counter.pop()
                current_section = parse_section(current_section, is_multipart)
                if not section_counter:
                    #sections.append(('0', current_section))
                    section_table[''] = current_section
                    return section_table, position
                #sections.append(('.'.join(map(str,section_counter)), current_section))
                section_table['.'.join(map(str,section_counter))] = current_section
                section_counter[-1] += 1
                current_section = []
                is_multipart = True
            else:
                current_section.append(value)
        raise ParseError("Unexpected end of data.")

    return parse_bodystructure

parse_bodystructure = import_bodystructure()

def hash_value(value):
    return hash_function(value).hexdigest()

def url_quote(value):
    return urlquote(value, safe='', encoding='utf-8')

def url_unquote(value):
    return urlunquote(value, encoding='utf-8', errors='ignore')

def imap_quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'

def imap_decode(value, encoding='utf-8'):
    if isinstance(value, bytes):
        if encoding:
            try:
                return value.decode(encoding, 'ignore')
            except LookupError:
                pass
        return value.decode('utf-8', 'ignore')
    return value

def imap_encode(value, encoding='utf-8'):
    if isinstance(value, str):
        return value.encode(encoding)
    return value


UID_RE = re.compile(b'UID\\s+([0-9]+)\\s*')
FLAGS_RE = re.compile(b'FLAGS\\s+\\(([^)]*)\\)\\s*')
BODYSTRUCTURE_RE = re.compile(b'(BODY(?:STRUCTURE)?)\\s+\\(', )
RESPONSE_TYPES_RE = re.compile(b'\\b(?:UID|FLAGS|BODY(?:STRUCTURE))\\b', )

class ImapMessage:

    def __init__(self, server, msg_id):
        self.server = server
        self.flags = ()
        self.uid = None
        self.structure = {}
        self._text = None
        self._html = None
        self._headers = {}
        self.parse_structure(msg_id)
        if not self.uid:
            raise ImapNoMessage("No UID for message #{}.".format(msg_id))

    def parse_structure(self, msg_id):
        logger.debug("fetching #{}", msg_id)
        fetch_result = self.server.mailbox.fetch(msg_id, "(UID FLAGS BODYSTRUCTURE)")
        logger.debug("got {} response", len(fetch_result[1]))
        for response in fetch_result[1]:
            position = response.find(b'(') + 1
            while position < len(response):
                if match := UID_RE.match(response, position):
                    self.uid = imap_decode(match.group(1))
                    next_position = match.end()
                elif match := FLAGS_RE.match(response, position):
                    self.flags = tuple(filter(None, imap_decode(match.group(1)).split(' ')))
                    next_position = match.end()
                elif match := BODYSTRUCTURE_RE.match(response, position):
                    self.structure, structure_size = parse_bodystructure(imap_decode(response[position:]))
                    next_position += structure_size
                elif match := RESPONSE_TYPES_RE.search(response, position):
                    next_position = match.start()
                else:
                    break
                if next_position <= position:
                    raise ImapBadResponse()
                position = next_position

    def body(self, sec_id=None):
        logger.debug("fetching UID {} BODY[{}]", self.uid, sec_id or "")
        section = self.structure[sec_id]
        fetch_result = self.server.mailbox.uid('FETCH',self.uid, "(BODY[{}])".format(sec_id or ""))
        for part in fetch_result[1]:
            content = part[1]
            if isinstance(part, tuple):
                if section.get('content-encoding') == 'base64':
                    content = base64_decode(content)
                elif section.get('content-encoding') == 'quoted-printable':
                    content = quopri_decode(content)
                return content
        raise ImapNoMessage("No body part {} in message UID {}".format(sec_id or "", self.uid))

    def header(self, name):
        if name in self._headers:
            return self._headers[name]
        logger.debug("fetching UID {} HEADER {}", self.uid, name)
        fetch_result = self.server.mailbox.uid('FETCH',self.uid, "(BODY[HEADER.FIELDS ({})])".format(name))
        for part in fetch_result[1]:
            if isinstance(part, tuple):
                enc_cont = part[1]
                dec_cont = decode_header(imap_decode(enc_cont[enc_cont.find(b':')+1:]
                                                     .replace(b'\r\n',b''),'us-ascii')
                                         )
                content = ''.join((imap_decode(raw,encoding) for raw,encoding in dec_cont))
                self._headers[name] = content
                return content
        return None

    def text(self):
        if self._text is not None:
            return self._text
        text_sections = [sec_id for sec_id, section in self.structure.items() 
                         if section['content-type'] == 'text/plain']
        if not text_sections:
            text_sections = [sec_id for sec_id, section in self.structure.items() 
                            if section['content-type'].startswith('text/')]
            if not text_sections:
                return None
        sec_id = text_sections[0]
        content = self.body(sec_id)
        content = imap_decode(content, self.structure[sec_id]['attributes'].get('charset'))
        self._text = content
        return content

    def html(self):
        if self._html is not None:
            return BeautifulSoup(self._html[0], 'html5lib', from_encoding=self._html[1])
        html_sections = [sec_id for sec_id, section in self.structure.items() 
                         if section['content-type'] == 'text/html']
        if html_sections:
            sec_id = html_sections[0]
            content = self.body(sec_id)
            self._html = (content, self.structure[sec_id]['attributes'].get('charset', 'utf-8'))
            return BeautifulSoup(content, 'html5lib', from_encoding=self._html[1])
        return None

    def attachments(self, section_id=None):
        if section_id is not None:
            section = self.structure.get(section_id)
            if not section:
                return None
            if 'content-disposition' in section and len(section['content-disposition']) > 1:
                return {'content-type':section['content-type'], **section['content-disposition'][1]}
            if 'attributes' in section:
                name = section['attributes'].get('name') or section.get('content-description') or section.get('content-id')
                if name:
                    return {'content-type':section['content-type'], 'filename':name}
            return {'content-type':section['content-type'], 'filename':"[{}]".format(section_id)}
        return ({'section':sec_id, 'content-type':section['content-type'],
                **(section['content-disposition'][1] or {})}
                for sec_id,section in self.structure.items()
                if 'content-disposition' in section and section['content-disposition'][0] == 'attachment')

    def url(self, section=None):
        msg_url = self.server.url() + "/;UID=" + self.uid
        if section:
            msg_url += "/;SECTION=" + url_quote(section)
        return msg_url

class ImapServer:

    def imap(self, username, password, server, port=None):
        self.mailbox = imaplib.IMAP4(server, port or imaplib.IMAP4_PORT)
        self.mailbox.login(username, password)
        self.auth = (username, password)
        self.set_base_url(server, port)

    def imaps(self, username, password, server, port=None):
        self.mailbox = imaplib.IMAP4_SSL(server, port or imaplib.IMAP4_SSL_PORT)
        self.mailbox.login(username, password)
        self.auth = (username, password, True)
        self.set_base_url(server, port, True)

    def logout(self):
        if self.mailbox:
            self.mailbox.logout()
            self.mailbox = None

    def set_base_url(self, server, port, ssl=False):
        self.base_url = (ssl and "imaps://" or "imap://") + server
        if port and port != imaplib.IMAP4_PORT:
            self.base_url += ":" + str(port)
        self.current_folder = ""

    def folder(self, name):
        if not self.mailbox:
            raise ImapNotLoggedInError()
        self.mailbox.select(utf7_encode(imap_quote(name)))
        self.current_folder = name

    def search(self, criteria):
        if not self.mailbox:
            raise ImapNotLoggedInError()
        search_result = self.mailbox.search(None, imap_encode(criteria))
        msgid_set = imap_decode(search_result[1][0]).split(' ')
        return (ImapMessage(self, msg_id) for msg_id in msgid_set if msg_id)

    def uid(self, msg_uids):
        if isinstance(msg_uids, str):
            msg_uids = [msg_uids]
        criteria = 'UID ' + ','.join(msg_uids)
        return self.search(criteria)

    def url(self):
        return self.base_url + "/" + url_quote(self.current_folder)

class InputEmail:
    """
    Get urls from email messages.
    """

    schema = {
        'type': 'object',
        'properties': {
            'username': {'type':'string'},
            'password': {'type':'string'},
            'server': {'type':'string'},
            'folder': {'type':'string', 'default':'INBOX'},
            'search': {'type':'string'},
            'subject': {'type': 'string'},
            'text': {'type': 'array', 'items': {'type':'string', 'format':'regex'}},
            'attachments': {'type': 'array', 'items': {'type':'string', 'format':'regex'}},
            'ssl': {'type': 'boolean'},
        },
        'required': ['username','password','server'],
        'additionalProperties': False,
    }

    def on_task_input(self, task, config):
        server = ImapServer()
        try:
            queue = []
            try:
                if not config.get('ssl', True):
                    server.imap(config['username'], config['password'], config['server'])
                else:
                    server.imaps(config['username'], config['password'], config['server'])
                if config.get('folder'):
                    server.folder(config['folder'])
                search_criteria = config.get('search', 'UNSEEN')
                for message in server.search(search_criteria):
                    if config.get('text'):
                        content = message.text()
                        if not content:
                            content_html = message.html()
                            if content_html:
                                content = content_html.text
                        if not content:
                            continue
                        link = None
                        for regexp in config['text']:
                            logger.debug("Checking against {}", regexp)
                            link_match = re.search(regexp, content)
                            if link_match:
                                link = link_match.group(1)
                                break
                        if not link:
                            continue
                        title = message.header('subject') or link
                        title_re = config.get('subject')
                        if title_re:
                            title_match = re.search(title_re, message.header('subject') or message.text())
                            if title_match:
                                title = title_match.group(1)
                        entry = Entry()
                        entry['url'] = link
                        entry['title'] = title
                        queue.append(entry)
                    elif config.get('attachments'):
                        for attachment in message.attachments():
                            if any(re.search(regexp, attachment['filename']) for regexp in config['attachments']):
                                entry = Entry()
                                entry['url'] = message.url(attachment['section'])
                                entry['title'] = attachment['filename']
                                entry['imap_auth'] = (config['username'], config['password'])
                                queue.append(entry)
            except imap_errors as err:
                logger.warning(repr(err))

            return queue
        finally:
            server.logout()

class OutputEmailAttachment:
    """
    Download attachments from email messages.
    """

    schema = {
        'oneOf': [
            {
                'type': 'object',
                'properties': {
                    'path': {'type':'string', 'format':'path'},
                    'overwrite': {'type':'boolean', 'default':False},
                    'temp': {'type':'string', 'format':'path'},
                    'filename': {'type':'string'},
                },
                'additionalProperties': False,
            },
            {'type':'string', 'format':'path'},
        ]
    }

    def process_config(self, config):
        """Return plugin configuration in cooked form."""
        if isinstance(config, str):
            config = {'path': config}
        if not isinstance(config, dict):
            config = {}
        if not config.get('path'):
            config['require_path'] = True
        return config

    def on_task_abort(self, task, config):
        self.cleanup_temp_files(task)

    def on_task_learn(self, task, config):
        self.cleanup_temp_files(task)

    def on_task_output(self, task, config):
        """Move downloaded content from temp folder to final destination."""
        config = self.process_config(config)
        for entry in task.accepted:
            try:
                self.output(task, entry, config)
            except plugin.PluginWarning as e:
                entry.fail()
                logger.error("Plugin error while writing: {}", e)
            except Exception as e:
                entry.fail()
                logger.error("Exception while writing: {}", e)

    def on_task_download(self, task, config):
        config = self.process_config(config)

        # set temporary download path
        tmp = config.get('temp', os.path.join(task.manager.config_base, 'temp'))
        self.get_temp_files(task, require_path=config.get('require_path'), tmp_path=tmp)

    def get_temp_files(self, task, require_path=False, tmp_path=tempfile.gettempdir()):
        """Download attachments into temporary folder."""
        for entry in task.accepted:
            self.get_temp_file(task, entry, require_path, tmp_path)

    def get_temp_file(self, task, entry, require_path=False, tmp_path=tempfile.gettempdir()):
        """Download entry attachment and store in temporary folder."""
        url = entry['url']
        if url.startswith('imaps:') or url.startswith('imap:'):
            if require_path and 'path' not in entry:
                logger.error("{} can't be downloaded, no path specified for entry", entry['title'])
                entry.fail('no path specified for entry')
        error = self.process_entry(task, entry, url, tmp_path)
        if error:
            entry.fail(error)

    def process_entry(self, task, entry, url, tmp_path):
        """Process `entry` using `url`."""
        try:
            if task.options.test:
                logger.info("Would download: {}", entry['title'])
            else:
                if not task.manager.unit_test:
                    logger.info("Downloading: {}", entry['title'])
                self.download_entry(task, entry, url, tmp_path)
        except (ImapBadResponse, ImapNoMessage, ImapNotLoggedInError) as e:
            logger.warning(repr(e))
            return 'Network error during request'
        except ValueError as e:
            msg = "ValueError {}".format(e)
            logger.warning(msg)
            logger.opt(exception=True).debug(msg)
            return msg

    def parse_imap_url(self, url):
        parts = urlsplit(url)
        params = [*map(url_unquote, parts.path.split('/;'))]
        folder = params[0].lstrip('/') if params[0] != '/' else 'INBOX'
        uid = None
        section = ''
        for parm in params:
            if parm.startswith('UID='):
                uid = parm[4:]
            elif parm.startswith('SECTION='):
                section = parm[8:]
        return parts,folder,uid,section

    def download_entry(self, task, entry, url, tmp_path):
        """Downloads `entry` by using `url`."""

        logger.debug("Downloading url '{}'", url)

        auth = entry['imap_auth']
        _url,folder,msg_uid,msg_section = self.parse_imap_url(url)
        server = ImapServer()
        if _url.scheme == "imaps":
            server.imaps(auth[0], auth[1], _url.netloc)
        else:
            server.imap(auth[0], auth[1], _url.netloc)
        if folder:
            server.folder(folder)
        if not msg_uid:
            entry.fail("URL missing message ID.")
            return
        for message in server.uid(msg_uid):
            attachment = message.attachments(msg_section)
            if not attachment:
                entry.fail("Mail attachment not found on server.")
                return

            try:
                tmp_path = os.path.expanduser(tmp_path)
            except RenderError as e:
                entry.fail("Could not set temp path. Error during string replacement: {}".format(e))
                return

            # Clean illegal characters from temp path name
            tmp_path = pathscrub(tmp_path)

            # If we are in test mode, report and return
            if task.options.test:
                logger.info("Would download attachment named `{}`", attachment['filename'])
                return

            # create if missing
            if not os.path.isdir(tmp_path):
                logger.debug("creating tmp_path {}", tmp_path)
                os.mkdir(tmp_path)
            # check for write access
            if not os.access(tmp_path, os.W_OK):
                raise plugin.PluginError("Not allowed to write to temp directory `{}`".format(tmp_path))
            # download and write data into a temp file
            tmp_dir = tempfile.mkdtemp(dir=tmp_path)
            fname = hash_value(url.encode('utf-8', 'replace'))
            datafile = os.path.join(tmp_dir, fname)
            outfile = io.open(datafile, 'wb')
            try:
                content = message.body(msg_section)
                outfile.write(content)
            except Exception as e:
                outfile.close()
                logger.debug("Download failed, removing datafile")
                os.remove(datafile)
                if isinstance(e, socket.timeout):
                    logger.error("Timeout while downloading attachment")
                else:
                    raise
            else:
                outfile.close()
                # Do a sanity check on downloaded file
                if os.path.getsize(datafile) == 0:
                    entry.fail("File {} is 0 bytes in size".format(datafile))
                    os.remove(datafile)
                    return
                # store temp filename into entry
                entry['file'] = datafile
                logger.debug("{} field file set to: {}", entry['title'], entry['file'])
            entry['mime-type'] = attachment['content-type']
            if 'size' in attachment:
                entry['content-length'] = attachment['size']
            entry['filename'] = attachment['filename']
            self.filename_ext_from_mime(entry)

    def output(self, task, entry, config):
        """Moves temp file into final destination."""
        if 'file' not in entry and not task.options.test:
            logger.debug("File missing, entry: {}", entry)
            raise plugin.PluginError("Entry `{}` has no associated temp file".format(entry['title']), logger)

        try:
            path = entry.get('path', config.get('path'))
            if not isinstance(path, str):
                raise plugin.PluginError("Invalid `path` in entry `{}`".format(entry['title']))
            if task.options.dl_path:
                path = task.options.dl_path
            try:
                path = os.path.expanduser(entry.render(path))
            except RenderError as e:
                entry.fail("Could not set path. Error during string replacement: {}".format(e))
                return
            path = pathscrub(path)
            if task.options.test:
                logger.info("Would write `{}` to `{}`", entry['title'], path)
                entry['location'] = os.path.join(path, 'TEST_MODE_NO_OUTPUT')
                return
            if not os.path.isdir(path):
                logger.debug("Creating directory {}", path)
                try:
                    os.makedirs(path)
                except:
                    raise plugin.PluginError("Cannot create path {}".format(path), logger)
            if not os.path.exists(entry['file']):
                logger.debug("entry: {}", entry)
                raise plugin.PluginWarning("Downloaded temp file `{}` doesn't exist!?".format(entry['file']))
            if config.get('filename'):
                try:
                    entry['filename'] = entry.render(config['filename'])
                    logger.debug("Set filename from config {}", entry['filename'])
                except RenderError as e:
                    entry.fail("Could not set filename. Error during string replacement: {}".format(e))
                    return
            elif not entry.get('filename'):
                entry['filename'] = entry['title']
                logger.debug("Set filename from title {}", entry['filename'])
                if 'mime-type' not in entry:
                    logger.warning("Unable to figure proper filename for {}. Using title.", entry['title'])
                else:
                    guess = mimetypes.guess_extension(entry['mime-type'])
                    if not guess:
                        logger.warning('Unable to guess extension with mime-type {}', guess)
                    else:
                        self.filename_ext_from_mime(entry)
            name = entry.get('filename', entry['title'])
            # Remove illegal characters from filename
            name = pathscrub(name).replace('/', ' ')
            if sys.platform.startswith('win'):
                name = name.replace('\\', ' ')
            # remove duplicate spaces
            name = ' '.join(name.split())
            # combine to full path + filename
            destfile = os.path.join(path, name)
            logger.debug('destfile: {}', destfile)

            if os.path.exists(destfile):
                import filecmp

                if filecmp.cmp(entry['file'], destfile):
                    logger.debug("Identical destination file '{}' already exists", destfile)
                elif not config.get('overwrite'):
                    logger.info("File `{}` already exists and is not identical, download failed.", destfile)
                    entry.fail("File `{}` already exists and is not identical.".format(destfile))
                    return
                else:
                    logger.debug("Overwriting already existing file {}", destfile)

            # move temp file
            logger.debug("moving {} to {}", entry['file'], destfile)
            try:
                shutil.move(entry['file'], destfile)
            except (IOError, OSError) as err:
                # ignore permission errors, see ticket #555
                import errno

                if not os.path.exists(destfile):
                    raise plugin.PluginError("Unable to write {}: {}".format(destfile, err))
                if err.errno != errno.EPERM and err.errno != errno.EACCES:
                    raise

            # store final destination as output key
            entry['location'] = destfile

        finally:
            self.cleanup_temp_file(entry)

    def filename_ext_from_mime(self, entry):
        # Tries to set filename extension from mime-type
        extensions = mimetypes.guess_all_extensions(entry['mime-type'], strict=False)
        if extensions:
            logger.debug("Mimetype guess for {} is {} ", entry['mime-type'], extensions)
            if entry.get('filename'):
                if any(entry['filename'].endswith(extension) for extension in extensions):
                    logger.debug("Filename {} extension matches to mime-type", entry['filename'])
                else:
                    extension = mimetypes.guess_extension(entry['mime-type'], strict=False)
                    logger.debug("Adding mime-type extension {} to {}", extension, entry['filename'])
                    entry['filename'] = entry['filename'] + extension
        else:
            logger.debug("Python doesn't know extension for mime-type: {}", entry['mime-type'])

    def cleanup_temp_files(self, task):
        for entry in task.entries + task.rejected + task.failed:
            self.cleanup_temp_file(entry)

    def cleanup_temp_file(self, entry):
        if 'file' in entry:
            if os.path.exists(entry['file']):
                logger.debug("Removing temp file {} from {}", entry['file'], entry['title'])
                os.remove(entry['file'])
            if os.path.exists(os.path.dirname(entry['file'])):
                shutil.rmtree(os.path.dirname(entry['file']))
            del entry['file']

@event('plugin.register')
def register_plugin():
    plugin.register(InputEmail, 'imap', api_ver=2)
    plugin.register(OutputEmailAttachment, 'imap_attachment', api_ver=2)
