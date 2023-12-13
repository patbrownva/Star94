from bs4 import BeautifulSoup
from email.header import decode_header
from urllib.parse import urljoin, urlsplit, quote as urlquote, unquote as urlunquote
from base64 import b64decode as base64_decode
from quopri import decodestring as quopri_decode
from hashlib import md5 as hash_function
import requests.exceptions
import mimetypes
import re
import io
import os
import tempfile
import shutil
import socket
import sys

class O365APIError(Exception):
    def __init__(self, result):
        logger.opt(exception=True).debug(str(result))
        self.error = result.get("error", "")
        self.error_description = result.get("error_description", "")
        self.correlation_id = result.get("correlation_id", "")
        super().__init__(self.error["message"])

class O365LibraryError(O365APIError):
    def __init__(self, exc):
        super().__init__(exc.kwargs)

class O365AuthError(O365APIError):
    def __init__(self):
        super().__init__({"error": "auth_error",
                          "message": "Office365 is not logged in."})

class O365HTTPError(O365APIError):
    def __init__(self, exc):
        super().__init__(exc.response.json())
        

import msal

from loguru import logger

from flexget import plugin
from flexget.entry import Entry
from flexget.event import event, add_event_handler, remove_event_handler
from flexget.utils.pathscrub import pathscrub
from flexget.utils.template import RenderError, render_from_entry
from flexget.config_schema import parse_interval

logger = logger.bind(name='o365')


def hash_value(value):
    return hash_function(value).hexdigest()

def url_quote(value):
    return urlquote(value, safe='', encoding='utf-8')

def url_unquote(value):
    return urlunquote(value, encoding='utf-8', errors='ignore')

def format_args(fmt_str, *args):
    sub_iter = iter(args)
    sub_cb = lambda match: str(next(sub_iter)).replace("'", "''")
    try:
        return re.sub('\?', sub_cb, fmt_str)
    except StopIteration:
        raise ValueError("Not enough parameters for format string.")

def stringify(val):
    if isinstance(val, str):
        return val
    try:
        ival = iter(val)
    except TypeError:
        return str(val)
    return ",".join(str(v) for v in ival)


class O365API:
    graph_api = "https://graph.microsoft.com/v1.0/"

    def __init__(self, session):
        self.requests = session

    def make_headers(self, headers):
        return headers

    def get_endpoint(self, endpoint, /, **parameters):
        logger.debug("get_endpoint: {} (Auth: {})", endpoint, self.requests.headers["Authorization"][:20])
        params = {"$"+name: stringify(value) for name, value in parameters.items()}
        headers = self.make_headers({})
        try:
            response = self.requests.get(self.graph_api + endpoint,
                                         params=params,
                                         headers=headers)
            result = response.json()
        except requests.exceptions.HTTPError as err:
            
            raise O365HTTPError(err)
        if "error" in result:
            raise O365APIError(result)
        if "@odata.nextLink" in result:
            value = []
            while result:
                if "error" in result:
                    raise O365APIError(result)
                value.extend(result["value"])
                if "@odata.nextLink" not in result:
                    break
                response = self.requests.get(result["@odata.nextLink"], headers=headers)
                result = response.json()
        elif "value" in result:
            value = result["value"]
        else:
            value = result
        return value

    def set_endpoint(self, endpoint, /, **params):
        logger.debug("set_endpoint: {} (Auth: {})", endpoint, self.requests.headers["Authorization"][:20])
        headers = self.make_headers({})
        try:
            response = self.requests.patch(self.graph_api + endpoint, json=params, headers=headers)
            result = response.json()
        except requests.exceptions.HTTPError as err:
            raise O365HTTPError(err)
        if not response.ok:
            raise O365APIError(result)
        return result

class O365MailAPI(O365API):

    def __init__(self, session, user=None):
        super().__init__(session)
        if user:
            self.base_endpoint = "users/" + url_quote(user)
        else:
            self.base_endpoint = "me"
        self.endpoint = self.base_endpoint

    def folder(self, name):
        logger.debug("Using folder {}", name)
        folders = self.get_endpoint(self.base_endpoint + "/mailFolders",
                                    filter=format_args("displayName eq '?'", name),
                                    select="id")
        self.endpoint = self.base_endpoint + "/mailFolders/" + folders[0]["id"]

    def messages(self, filter=None, search=None):
        logger.debug("Retrieving messages with filter: {}", filter)
        messages = self.get_endpoint(self.endpoint + "/messages", filter=filter, select="id")
        return [O365MailMessage(self, self.endpoint + "/messages/" + msg["id"]) for msg in messages]

    def make_headers(self, headers):
        headers["Prefer"] = "outlook.body-content-type=text"
        return headers

class O365MailMessage:

    def __init__(self, api, endpoint):
        self.api = api
        self.endpoint = endpoint
        self._text = None
        self._html = None
        self._subject = None
        self._headers = {}

    def body(self):
        try:
            logger.debug("Retrieving message body.")
            message = self.api.get_endpoint(self.endpoint, select=("body","subject"))
        except msal.exceptions.MsalError as e:
            raise O365LibraryError(e)
        if message["body"]["contentType"] == "text":
            self._text = message["body"]["content"]
        if message["body"]["contentType"] == "html":
            self._html = message["body"]["content"]
        self._subject = message["subject"]

    def subject(self):
        if self._subject is None:
            self.body()
        return self._subject

    def text(self):
        if self._text is None:
            self.body()
        return self._text

    def header(self, name):
        if name in self._headers:
            return self._headers[name]

    def attachments(self):
        attachments = self.api.get_endpoint(self.endpoint + "/attachments",
                                            filter="isInline eq false",
                                            select=("id","name"))
        # isof operator not supported by GraphAPI so have to filter by hand
        return [attachment for attachment in attachments if attachment["@odata.type"] == "#microsoft.graph.fileAttachment"]

    def isRead(self, value=None):
        if value is None:
            try:
                message = self.api.get_endpoint(self.endpoint, select=("isRead"))
                return message["isRead"]
            except msal.exceptions.MsalError as e:
                raise O365LibraryError(e)
        else:
            try:
                self.api.set_endpoint(self.endpoint, isRead=bool(value))
            except msal.exceptions.MsalError as e:
                raise O365LibraryError(e)

    def url(self, attachment=None):
        if attachment is not None:
            attachment = "/attachments/" + attachment + "/$value"
        else:
            attachment = ""
        return self.api.graph_api + self.endpoint + attachment

class O365Auth:
    scopes = ["https://graph.microsoft.com/.default"]

    def __init__(self, client_id, secret, authority):
        try:
            logger.debug("Starting MSAL client.")
            self.app = msal.ConfidentialClientApplication(client_id,
                                                          client_credential=secret,
                                                          authority=authority)
        except msal.exceptions.MsalError as err:
            raise O365LibraryError(err)
        self.bearer_token = None

    def login(self, user=None):
        try:
            logger.debug("Acquiring client token.")
            result = self.app.acquire_token_silent(self.scopes, account=user)
            if not result:
                result = self.app.acquire_token_for_client(scopes=self.scopes)
            if "access_token" in result:
                self.bearer_token = 'Bearer ' + result["access_token"]
                logger.debug("Got token: {}", self.bearer_token[:20])
            else:
                raise O365APIError(result)
        except msal.exceptions.MsalError as err:
            raise O365LibraryError(err)
        return self.bearer_token

    def logout(self):
        self.bearer_token = None

    @property
    def token(self):
        if self.bearer_token is None:
            raise O365AuthError()
        return self.bearer_token


class StartLogin:
    """
    Handle logging in to Microsoft GraphAPI.
    For Office365 plugins.
    """

    def __init__(self):
        self.apps = {}
        self.plugins = {}
        self._add_events()

    schema = {
        'type': 'object',
        'properties': {
            'client_id': {'type':'string'},
            'secret': {'type':'string'},
            'authority': {'type':'string'},
            'download': {'type':'boolean','default':False},
        },
        'required': ['client_id','secret','authority'],
        'additionalProperties': False,
    }

    def on_task_start(self, task, config):
        try:
            self.apps[task.name] = O365Auth(config['client_id'], config['secret'], config['authority'])
            if config['download']:
                self.plugins[task.name] = ('outlook', 'outlook_attachment', 'download')
            else:
                self.plugins[task.name] = ('outlook', 'outlook_attachment')
        except O365APIError as err:
            logger.warning("O365APIError: {}: {}", err.error, err.error_description)

    #def on_task_exit(self, task, config):
    #    self._remove_events()

    #def on_task_abort(self, task, config):
    #    self._remove_events()

    def _add_events(self):
        add_event_handler('task.execute.before_plugin', self.on_before_plugin)
        add_event_handler('task.execute.after_plugin', self.on_after_plugin)

    def _remove_events(self):
        remove_event_handler('task.execute.before_plugin', self.on_before_plugin)
        remove_event_handler('task.execute.after_plugin', self.on_after_plugin)

    def on_before_plugin(self, task, plugin_name):
        if task.name in self.apps and plugin_name in self.plugins[task.name]:
            try:
                token = self.apps[task.name].login()
                task.requests.headers["Authorization"] = token
            except O365APIError as err:
                logger.warning("O365APIError: {}: {}", err.error, err.error_description)

    def on_after_plugin(self, task, plugin_name):
        if task.name in self.apps and plugin_name in self.plugins[task.name]:
            del task.requests.headers["Authorization"]


class InputEmail:
    """
    Get urls from email messages.
    """

    schema = {
        'type': 'object',
        'properties': {
            'user': {'type':'string'},
            'folder': {'type':'string', 'default':'INBOX'},
            'filter': {'type':'string'},
            'search': {'type':'string'},
            'subject': {'type': 'string'},
            'text': {'type': 'array', 'items': {'type':'string', 'format':'regex'}},
            'attachments': {'type': 'array', 'items': {'type':'string', 'format':'regex'}},
       },
        'required': ['user'],
        'additionalProperties': False,
    }

    def on_task_input(self, task, config):
        try:
            api = O365MailAPI(task.requests, config['user'])
            queue = []
            if config.get('folder'):
                api.folder(config['folder'])
            filter_criteria = config.get('filter', 'isRead eq false')
            for message in api.messages(filter=filter_criteria):
                try:
                    message.isRead(True)
                except O365APIError as err:
                    logger.warning("Error setting isRead flag: {}", str(err))
                if config.get('text'):
                    content = message.text()
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
                    title = message.subject() or link
                    title_re = config.get('subject')
                    if title_re:
                        title_match = re.search(title_re, message.subject() or message.text())
                    if title_match:
                            title = title_match.group(1)
                    entry = Entry()
                    entry['url'] = link
                    entry['title'] = title
                    queue.append(entry)
                elif config.get('attachments'):
                    for attachment in message.attachments():
                        if any(re.search(regexp, attachment['name']) for regexp in config['attachments']):
                            logger.debug("Adding attachment: {}", attachment['name'])
                            entry = Entry()
                            entry['url'] = message.url(attachment['id'])
                            entry['title'] = attachment['name']
                            entry['filename'] = attachment['name']
                            queue.append(entry)
        except O365APIError as err:
            logger.warning("O365APIError: {}: {}", err.error, err.error_description)
        return queue

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
        if url.startswith(O365API.graph_api):
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
        except O365APIError as err:
            logger.warning("O365APIError: {}: {}", err.error, err.error_description)
            return 'Network error during request'
        except ValueError as e:
            msg = "ValueError {}".format(e)
            logger.warning(msg)
            logger.opt(exception=True).debug(msg)
            return msg

    def download_entry(self, task, entry, url, tmp_path):
        """Downloads `entry` by using `url`."""

        logger.debug("Downloading url '{}'", url)

        api = O365MailAPI(task.requests)

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
            attachment = api.get_endpoint(url)
            outfile.write(attachment)
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
    plugin.register(StartLogin, 'office365', api_ver=2)
    plugin.register(InputEmail, 'outlook', api_ver=2)
    #plugin.register(OutputEmailAttachment, 'outlook_attachment', api_ver=2)
