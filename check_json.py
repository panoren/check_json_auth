#!/usr/bin/env python3

import nagiosplugin
import json
from flatten_json import flatten
import urllib.request
import argparse
import logging
import re
import datetime as dt
import pendulum
import sys

class CheckJSON(nagiosplugin.Resource):
    def __init__(self=None, url=None, jsn=None, key=None, match=None, function=None, regex=None, timezone=None, timeformat=None, timeduration=None, usr=None, pwd=None, headers={}):

        self.url = url
        self.key = key
        self.match = match
        self.function = function
        self.regex = regex
        self.timezone = timezone
        self.timeformat = timeformat
        self.timeduration = timeduration
        self.json = jsn
        self.flatJSON = {}
        self.timestamp = None
        self.stringJSON = None
        self.seconds = 0
        self.minutes = 0
        self.hours = 0
        self.days = 0
        self.tdiff = 0
        self.headers = headers
        self.usr = usr
        self.pwd = pwd
    def _GetJSON(self):
        try:
            if self.url is not None:
                password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                password_mgr.add_password(None, self.url, self.usr, self.pwd)
                handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
                opener = urllib.request.build_opener(handler)
                opener.open(self.url)
                urllib.request.install_opener(opener)
                #print(self.headers)
                for kk, vv in self.headers.items():
                    opener.add_header(kk, vv)
                with urllib.request.urlopen(self.url) as response:
                #with urllib.request.urlopen(self.url) as response:
                    rawJSON = json.loads(response.read().decode())
                    logging.debug("JSON Data: %s", str(rawJSON))
                    return rawJSON
            else:
                rawJSON = json.loads(self.json)
                return rawJSON

        except Exception as err:
            logging.critical("Unable to retrieve JSON data: %s", str(err))
            sys.exit()

    def _FlattenJSON(self):
        try:
            flatJSON = flatten(self.json, '.')
            logging.debug("Flattened JSON: %s", str(flatJSON))
            return flatJSON
        except Exception as err:
            logging.critical('Unable to flatten JSON data: %s', str(err))
            sys.exit()

    def _ConvertSeconds(self):
        minutes = self.seconds / 60
        hours = minutes / 60
        days = hours / 60
        return {'days': days, 'hours': hours, 'minutes': minutes, 'seconds': self.seconds}

    def _DateDifference(self):
        try:
            regex = re.compile(self.regex, re.IGNORECASE)
            tz = pendulum.timezone(self.timezone)
            timestamp = regex.search(self.timestamp)
            timestamp = str(timestamp.group(0))
            
            logging.debug('Timestamp: %s, Timestamp: %s, Regex: %s', str(timestamp), str(tz), str(regex))

            if timestamp:
                d1 = pendulum.now(tz)
                d2 = pendulum.from_format(timestamp, self.timeformat, tz)
                logging.debug("D1: %s, D2: %s", d1, d2)
                seconds = abs((d1 - d2).total_seconds())
                return seconds
            else:
                logging.error('Invalid timestamp or regex match')

        except Exception as err:
            logging.error("Unable to get datetime difference: %s", str(err))
            sys.exit()

    def GetFunction(self):
        self.json = self._GetJSON()
        self.flatJSON = self._FlattenJSON()

        if not isinstance(self.flatJSON[self.key], bool) and (isinstance(self.flatJSON[self.key], int) or isinstance(self.flatJSON[self.key], float)):
            self.function = 'integer'

        else:
            stringJSON = str(self.flatJSON[self.key])
            regex = re.compile(self.regex)

            if regex.match(stringJSON):
                self.function = 'timediff'
            else:
                self.function = 'match'

        return self.function

    def probe(self):
        self.json = self._GetJSON()
        self.flatJSON = self._FlattenJSON()

        if self.function == 'timediff':
            self.timestamp = self.flatJSON[self.key]
            self.seconds = self._DateDifference()
            self.tdiff = self._ConvertSeconds()[self.timeduration]
            yield nagiosplugin.Metric('timediff', self.tdiff, min=0)

        elif self.function == 'match':
            stringJSON = str(self.flatJSON[self.key])
            regex = re.compile(self.match, re.IGNORECASE)
            strMatch = True if regex.match(stringJSON) else False
            yield nagiosplugin.Metric('match', strMatch)

        elif self.function == 'integer':
            intJSON = int(self.flatJSON[self.key])
            yield nagiosplugin.Metric('integer', intJSON)

        else:
            logging.critical('Invalid function: Please enter a valid argument.')
            sys.exit()


def parse_headers(headers_list, delimiter='='):
    headers = dict()
    for each in headers_list:
        key, value = each.split(delimiter)
        headers[key] = value

    return headers


@nagiosplugin.guarded
def main():
    argp = argparse.ArgumentParser(description=__doc__)
    argp.add_argument('-u',  '--url',           help='URL to obtain JSON data.')
    argp.add_argument('-j',  '--json',          help='If not specifying a URL, you can specify the JSON string directly.')
    argp.add_argument('-k',  '--key',           required=True, help='json key(s) using "." delimination.')
    argp.add_argument('-f',  '--function',      default='auto', help='Function comparison to be performed (timediff|match|integer). Defaults to "auto"')
    argp.add_argument('-R',  '--regex',         default='[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}', help='regex pattern for pulling timestamp from JSON. Should be the regex equivalent of timeformat. Defaults to yyyy-mm-ddTHH:MM:SS')
    argp.add_argument('-tf', '--timeformat',    default='YYYY-MM-DDTHH:mm:ss', help='Time format pattern: (https://pendulum.eustace.io/docs/#formatter)')
    argp.add_argument('-td', '--timeduration',  default='seconds', help='Output format of timediff (days|hours|minutes|seconds). Default is seconds.')
    argp.add_argument('-tz', '--timezone',      default='Etc/UTC', help='IANA time zones (https://en.wikipedia.org/wiki/List_of_tz_database_time_zones#List). Default is Etc/UTC')
    argp.add_argument('-m',  '--match',         default='', help='string or regex pattern for comparison against the JSON key value')
    argp.add_argument('-w',  '--warning')
    argp.add_argument('-c',  '--critical')
    argp.add_argument('-v',  '--verbose',       action="store_true")
    argp.add_argument('-D',  '--debug',         default='INFO', action='store_true')
    argp.add_argument('-H',  '--header',        default=[], type=str, nargs='+', help='Add custom Header(s)')
    argp.add_argument('-U',  '--username',      action='store')
    argp.add_argument('-P',  '--password',      action='store')
    args = argp.parse_args()

    parsed_headers = parse_headers(args.header)

    logging.basicConfig(format='%(asctime)s [%(levelname)s] {%(funcName)s} %(message)s', level=args.debug)

    if args.function == 'auto':
        args.function = CheckJSON(url=args.url, jsn=args.json, key=args.key, function=args.function, regex=args.regex, usr=args.username, pwd=args.password, headers=parsed_headers).GetFunction()
        logging.debug('Autofunction: %s', args.function)

    if args.function == 'timediff':
        check = nagiosplugin.Check(
            CheckJSON(url=args.url, jsn=args.json, key=args.key, function=args.function, regex=args.regex, timezone=args.timezone, timeformat=args.timeformat, timeduration=args.timeduration, usr=args.username, pwd=args.password, headers=parsed_headers),
            nagiosplugin.ScalarContext('timediff', args.warning, args.critical)
        )
        check.main()

    elif args.function == 'match':
        check = nagiosplugin.Check(
            CheckJSON(url=args.url, jsn=args.json, key=args.key, match=args.match, function=args.function, usr=args.username, pwd=args.password, headers=parsed_headers),
            nagiosplugin.ScalarContext('match' , '1:', '1:')
        )
        check.main()
    
    elif args.function == 'integer':
        check = nagiosplugin.Check(
            CheckJSON(url=args.url, jsn=args.json, key=args.key, function=args.function, usr=args.username, pwd=args.password, headers=parsed_headers),
            nagiosplugin.ScalarContext('integer', args.warning, args.critical)
        )
        check.main()
        

if __name__ == '__main__':
    main()
