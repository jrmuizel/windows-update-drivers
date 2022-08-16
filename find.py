# From https://github.com/jborean93/packer-windoze/blob/49a43491377f3a0a322644462d8ef40ea7ecb42a/roles/packer-setup/lookup_plugins/windows_update.py
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from ansible.errors import AnsibleLookupError
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.urls import open_url
from ansible.plugins.lookup import LookupBase
from ansible.module_utils.six.moves import urllib
import re
import time
import contextlib
import datetime
import json
import traceback
import uuid

BS_IMP_ERR = None
try:
    from bs4 import BeautifulSoup
    HAS_BS = True
except ImportError:
    BS_IMP_ERR = traceback.format_exc()
    HAS_BS = False

CATALOG_URL = 'https://www.catalog.update.microsoft.com/'
DOWNLOAD_PATTERN = DOWNLOAD_PATTERN = re.compile(r'\[(\d*)\]\.url = [\"\'](http[s]?://.*download\.windowsupdate\.com/[^\'\"]*)')
PRODUCT_SPLIT_PATTERN = re.compile(r',(?=[^\s])')

@contextlib.contextmanager
def urlopen(*args, **kwargs):
    resp = open_url(*args, http_agent='packer-windoze/%s' % __name__, timeout=100,**kwargs)
    try:
        yield resp
    finally:
        resp.close()

class WUDownloadInfo:

    def __init__(self, download_id, url, raw):
        """
        Contains information about an individual download link for an update. An update might have multiple download
        links available and this keeps track of the metadata for each of them.
        :param download_id: The ID that relates to the download URL.
        :param url: The download URL for this entry.
        :param raw: The raw response text of the downloads page.
        """
        self.url = url
        self.digest = None
        self.architectures = None
        self.languages = None
        self.long_languages = None
        self.file_name = None

        attribute_map = {
            'digest': 'digest',
            'architectures': 'architectures',
            'languages': 'languages',
            'long_languages': 'longLanguages',
            'file_name': 'fileName',
        }
        for attrib_name, raw_name in attribute_map.items():
            regex_pattern = r"\[%s]\.%s = ['\"]([\w\-\.=+\/\(\) ]*)['\"];" % (
            re.escape(download_id), re.escape(raw_name))
            regex_match = re.search(regex_pattern, raw)
            if regex_match:
                setattr(self, attrib_name, regex_match.group(1))

    def __str__(self):
        return to_native("%s - %s" % (self.file_name or "unknown", self.long_languages or "unknown language"))


class WindowsUpdate:

    def __init__(self, raw_element):
        """
        Stores information about a Windows Update entry.
        :param raw_element: The raw XHTML element that has been parsed by BeautifulSoup4.
        """
        cells = raw_element.find_all('td')

        self.title = cells[1].get_text().strip()

        # Split , if there is no space ahead.
        products = cells[2].get_text().strip()
        self.products = list(filter(None, re.split(PRODUCT_SPLIT_PATTERN, products)))

        self.classification = cells[3].get_text().strip()
        self.last_updated = datetime.datetime.strptime(cells[4].get_text().strip(), '%m/%d/%Y')
        self.version = cells[5].get_text().strip()
        self.size = int(cells[6].find_all('span')[1].get_text().strip())
        self.id = uuid.UUID(cells[7].find('input').attrs['id'])
        self._details = None
        self._architecture = None
        self._hw_ids = None
        self._description = None
        self._download_urls = None
        self._kb_numbers = None
        self._more_information = None
        self._msrc_number = None
        self._msrc_severity = None
        self._support_url = None

    @property
    def architecture(self):
        """ The architecture of the update. """
        if not self._architecture:
            details = self._get_details()
            raw_arch = details.find(id='ScopedViewHandler_labelArchitecture_Separator')
            self._architecture = raw_arch.next_sibling.strip()

        return self._architecture


    @property
    def hw_ids(self):
        """ The hardware ids. """
        if not self._hw_ids:
            details = self._get_details()
            raw_hw_ids = details.find(id='driverhwIDs').find_all('div')
            ids = []
            for i in raw_hw_ids:
                ids.append(i.get_text().strip())
            self._hw_ids = ids

        return self._hw_ids

    @property
    def description(self):
        """ The description of the update. """
        if not self._description:
            details = self._get_details()
            self._description = details.find(id='ScopedViewHandler_desc').get_text()

        return self._description

    @property
    def download_url(self):
        """ The download URL of the update, will fail if the update contains multiple packages. """
        download_urls = self.get_download_urls()

        if len(download_urls) != 1:
            raise ValueError("Expecting only 1 download link for '%s', received %d. Use get_download_urls() and "
                             "filter it based on your criteria." % (str(self), len(download_urls)))

        return download_urls[0].url

    @property
    def kb_numbers(self):
        """ A list of KB article numbers that apply to the update. """
        if self._kb_numbers is None:
            details = self._get_details()
            raw_kb = details.find(id='ScopedViewHandler_labelKBArticle_Separator')

            # If no KB's apply then the value will be n/a. Technically an update can have multiple KBs but I have
            # not been able to find an example of this so cannot test that scenario.
            self._kb_numbers = [int(n.strip()) for n in list(raw_kb.next_siblings) if n.strip().lower() != 'n/a']

        return self._kb_numbers

    @property
    def more_information(self):
        """ Typically the URL of the KB article for the update but it can be anything. """
        if self._more_information is None:
            details = self._get_details()
            raw_info = details.find(id='ScopedViewHandler_labelMoreInfo_Separator')
            self._more_information = list(raw_info.next_siblings)[1].get_text().strip()

        return self._more_information

    @property
    def msrc_number(self):
        """ The MSRC Number for the update, set to n/a if not defined. """
        if self._msrc_number is None:
            details = self._get_details()
            raw_info = details.find(id='ScopedViewHandler_labelSecurityBulliten_Separator')
            self._msrc_number = list(raw_info.next_siblings)[0].strip()

        return self._msrc_number

    @property
    def msrc_severity(self):
        """ THe MSRC severity level for the update, set to Unspecified if not defined. """
        if self._msrc_severity is None:
            details = self._get_details()
            self._msrc_severity = details.find(id='ScopedViewHandler_msrcSeverity').get_text().strip()

        return self._msrc_severity

    @property
    def support_url(self):
        """ The support URL for the update. """
        if self._support_url is None:
            details = self._get_details()
            raw_info = details.find(id='ScopedViewHandler_labelSupportUrl_Separator')
            self._support_url = list(raw_info.next_siblings)[1].get_text().strip()

        return self._support_url

    def get_download_urls(self):
        """
        Get a list of WUDownloadInfo objects for the current update. These objects contain the download URL for all the
        packages inside the update.
        """
        if self._download_urls is None:
            update_ids = json.dumps({
                'size': 0,
                'updateID': str(self.id),
                'uidInfo': str(self.id),
            })
            data = to_bytes(urllib.parse.urlencode({'updateIDs': '[%s]' % update_ids}))

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            with urlopen('%s/DownloadDialog.aspx' % CATALOG_URL, data=data,
                         headers=headers) as resp:
                resp_text = to_text(resp.read()).strip()

            link_matches = re.findall(DOWNLOAD_PATTERN, resp_text)
            if len(link_matches) == 0:
                raise ValueError("Failed to find any download links for '%s'" % str(self))

            download_urls = []
            for download_id, url in link_matches:
                download_urls.append(WUDownloadInfo(download_id, url, resp_text))

            self._download_urls = download_urls

        return self._download_urls

    def _get_details(self):
        if not self._details:
            while True:
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
                print('%s/ScopedViewInline.aspx?updateid=%s' % (CATALOG_URL, str(self.id)))
                with urlopen('%s/ScopedViewInline.aspx?updateid=%s' % (CATALOG_URL, str(self.id)),
                             headers=headers) as resp:
                    resp_text = to_text(resp.read()).lstrip()
                #print(resp_text)
                #print(resp.code)
                self._details = BeautifulSoup(resp_text, 'html.parser')
                if self._details.find('ctl00_catalogBody_textNoUpdate'):
                    raise 'no-update'

                if self._details.find(id='ctl00_catalogBody_errorHandler_error500'):
                    print("500 errror retrying")
                    time.sleep(1)
                else:
                    break

        return self._details

    def __str__(self):
        return self.title

def find_updates(search, all_updates=False, sort=None, sort_reverse=False, data=None):
    """
    Generator function that yields WindowsUpdate objects for each update found on the Microsoft Update catalog.
    Yields a list of updates from the Microsoft Update catalog. These updates can then be downloaded locally using the
    .download(path) function.
    :param search: The search string used when searching the update catalog.
    :param all_updates: Set to True to continue to search on all pages and not just the first 25. This can dramatically
        increase the runtime of the script so use with caution.
    :param sort: The field name as seen in the update catalog GUI to sort by. Setting this will result in 1 more call
        to the catalog URL.
    :param sort_reverse: Reverse the sort after initially sorting it. Setting this will result in 1 more call after
        the sort call to the catalog URL.
    :param data: Data to post to the request, used when getting all pages
    :return: Yields the WindowsUpdate objects found.
    """
    search_safe = urllib.parse.quote(search)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    if data:
        data = to_bytes(urllib.parse.urlencode(data))

    url = '%s/Search.aspx?q=%s' % (CATALOG_URL, search_safe)
    with urlopen(url, data=data, headers=headers) as resp:
        resp_text = to_text(resp.read()).lstrip()

    catalog = BeautifulSoup(resp_text, 'html.parser')

    # If we need to perform an action (like sorting or next page) we need to add these 4 fields that are based on the
    # original response received.
    def build_action_data(action):
        data = {
            '__EVENTTARGET': action,
        }
        for field in ['__EVENTARGUMENT', '__EVENTVALIDATION', '__VIEWSTATE', '__VIEWSTATEGENERATOR']:
            element = catalog.find(id=field)
            if element:
                data[field] = element.attrs['value']

        return data

    raw_updates = catalog.find(id='ctl00_catalogBody_updateMatches').find_all('tr')
    headers = raw_updates[0]  # The first entry in the table are the headers which we may use for sorting.

    if sort:
        # Lookup the header click JS targets based on the header name to sort.
        header_links = headers.find_all('a')
        event_targets = dict((l.find('span').get_text(), l.attrs['id'].replace('_', '$')) for l in header_links)
        data = build_action_data(event_targets[sort])

        sort = sort if sort_reverse else None  # If we want to sort descending we need to sort it again.
        for update in find_updates(search, all_updates, sort=sort, data=data):
            yield update
        return

    for u in raw_updates[1:]:
        yield WindowsUpdate(u)

    # ctl00_catalogBody_nextPage is set when there are no more updates to retrieve.
    last_page = catalog.find(id='ctl00_catalogBody_nextPage')
    if not last_page and all_updates:
        data = build_action_data('ctl00$catalogBody$nextPageLinkText')
        for update in find_updates(search, True, data=data):
            yield update

device = "9a78"
#subsys = "86941043"
for k in find_updates("PCI\VEN_8086&DEV_0162", all_updates=True, sort="Version"):
#for k in find_updates("PCI\VEN_8086&DEV_9A78 27.20.100.9268", all_updates=True, sort="Version"):
#for k in find_updates("PCI\VEN_8086&DEV_3E9b\SUBSYS_086f1028", all_updates=True, sort="Version"):
#for k in find_updates("PCI\VEN_8086&DEV_%s" % device, all_updates=True, sort="Version", sort_reverse=True):
#for k in find_updates("26.20.100.7323 DEV_%s" % device, all_updates=True, sort="Version", sort_reverse=True):
#for k in find_updates("20.19.15.4390", all_updates=True, sort="Version", sort_reverse=True):
    print(k)
    print(k.version, k.architecture, k.download_url)
    print(k.hw_ids)
    for i in k.hw_ids:
        if device in i:
            print("\t", i)
