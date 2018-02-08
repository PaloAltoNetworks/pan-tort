#!/usr/bin/env python
#
# Copyright (c) 2015 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

from __future__ import print_function
import datetime
import getopt
import json
import logging
import os
import pprint
import sys
import json
import time


libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, os.pardir, 'lib')]
import pan.afapi

debug = 0


def panafapi_hacked(hostname, api_key, action, hashtype, hashvalue):


    options = {
        'sessions': False,
        'aggregate': False,
        'histogram': False,
        'session': None,
        'samples': False,
        'sample_analysis': False,
        'top_tags': False,
        'tags': False,
        'tag': None,
        'export': False,
        'json_requests': [],
        'json_request': None,
        'json_request_obj': None,
        'num_results': None,
        'scope': None,
        'hash': None,
        'terminal': False,
        'api_key': api_key,
        'api_version': None,
        'hostname': hostname,
        'ssl': False,
        'print_python': False,
        'print_json': True,
        'debug': 0,
        'panrc_tag': None,
        'timeout': None,
        }


    if action == 'find_hash':

        options['samples'] = True
        lastYear = int(time.strftime("%Y")) - 1
        query_arg = '{{"query":{{"operator":"all","children":[{{"field":"sample.{0}","operator":"is","value":"{1}"}}]}},"scope":"global","size":1,"from":0,"sort":{{"create_date":{{"order":"desc"}}}}}}'.format(hashtype, hashvalue)

    elif action == 'sample_analysis':
        options['sample_analysis'] = True
        options['hash'] = hashvalue
        query_arg = '{"coverage":"true"}'
  
    options['json_requests'].append(process_arg(query_arg))

    if options['json_requests']:
        obj = {}
        
        for r in options['json_requests']:
            try:
                x = json.loads(r)
            except ValueError as e:
                print('%s: %s' % (e, r), file=sys.stderr)
                sys.exit(1)
            obj.update(x)

        try:
            options['json_request'] = json.dumps(obj)
            options['json_request_obj'] = obj
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)      

    try:
        afapi = pan.afapi.PanAFapi(panrc_tag=options['panrc_tag'],
                                   api_key=options['api_key'],
                                   api_version=options['api_version'],
                                   hostname=options['hostname'],
                                   timeout=options['timeout'],
                                   verify_cert=options['ssl'])

    except pan.afapi.PanAFapiError as e:
        print('pan.afapi.PanAFapi:', e, file=sys.stderr)
        sys.exit(1)

    if options['json_request'] is None:
        options['json_request'] = '{}'
        options['json_request_obj'] = {}

    if options['samples']:
        af_output = search_results(afapi, options,
                       afapi.samples_search_results)

    if options['sample_analysis']:
        af_output = sample_analysis(afapi, options)   
        

    elif options['tag'] is not None:
        af_output = tag(afapi, options)

    return af_output


def sample_analysis(afapi, options):
    try:
        action = 'sample-analysis'
        r = afapi.sample_analysis(data=options['json_request'],
                                  sampleid=options['hash'])
        print_status(action, r)
        af_output = print_response(r, options)
        exit_for_http_status(r)
        return af_output

    except pan.afapi.PanAFapiError as e:
        print_exception(action, e)
        sys.exit(1)

def tag(afapi, options):
    try:
        action = 'tag'
        r = afapi.tag(tagname=options['tag'])
        print_status(action, r)
        af_output = print_response(r, options)
        exit_for_http_status(r)
        return af_output

    except pan.afapi.PanAFapiError as e:
        print_exception(action, e)
        sys.exit(1)


def search_results(afapi,
                   options,
                   search):
    request = options['json_request']

    if options['num_results'] is not None:
        try:
            obj = json.loads(request)
            obj['size'] = options['num_results']
            request = json.dumps(obj)
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

    if options['scope'] is not None:
        try:
            obj = json.loads(request)
            obj['scope'] = options['scope']
            request = json.dumps(obj)
        except ValueError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

    try:
        for r in search(data=request, terminal=options['terminal']):
            print_status(r.name, r)
            if debug > 2:
                af_output = print_response(r, options)
        if debug <= 2:
            af_output = print_response(r, options)

    except pan.afapi.PanAFapiError as e:
        print_exception(search.__name__, e)
        sys.exit(1)
    return af_output

def print_exception(action, e):
    print('%s:' % action, end='', file=sys.stderr)
    print(' "%s"' % e, file=sys.stderr)


def print_status(action, r):
    print('%s:' % action, end='', file=sys.stderr)

    if r.http_code is not None:
        print(' %s' % r.http_code, end='', file=sys.stderr)
    if r.http_reason is not None:
        print(' %s' % r.http_reason, end='', file=sys.stderr)

    if r.http_headers is not None:
        # XXX
        content_type = r.http_headers.get('content-type')
        if False and content_type is not None:
            print(' %s' % content_type, end='', file=sys.stderr)
        length = r.http_headers.get('content-length')
        if length is not None:
            print(' %s' % length, end='', file=sys.stderr)

    if r.json is not None:
        if 'message' in r.json:
            print(' "%s"' % r.json['message'],
                  end='', file=sys.stderr)

        if 'af_complete_percentage' in r.json:
            print(' %s%%' % r.json['af_complete_percentage'],
                  end='', file=sys.stderr)

        if 'hits' in r.json:
            hits = len(r.json['hits'])
            print(' hits=%d' % hits, end='', file=sys.stderr)
        elif 'tags' in r.json:
            print(' tags=%d' % len(r.json['tags']),
                  end='', file=sys.stderr)
        elif 'top_tags' in r.json:
            print(' top_tags=%d' % len(r.json['top_tags']),
                  end='', file=sys.stderr)
        elif 'export_list' in r.json:
            print(' export_list=%d' % len(r.json['export_list']),
                  end='', file=sys.stderr)

        if 'total' in r.json:
            print(' total=%d' % r.json['total'],
                  end='', file=sys.stderr)
        elif 'total_count' in r.json:
            print(' total_count=%d' % r.json['total_count'],
                  end='', file=sys.stderr)

        if 'took' in r.json and r.json['took'] is not None:
            d = datetime.timedelta(milliseconds=r.json['took'])
            print(' time=%s' % str(d)[:-3],
                  end='', file=sys.stderr)

        if 'af_message' in r.json:
            print(' "%s"' % r.json['af_message'],
                  end='', file=sys.stderr)

    print(file=sys.stderr)


def print_response(r, options):
    if r.http_text is None:
        return

    if r.http_headers is not None:
        x = r.http_headers.get('content-type')
        if x is None:
            return

    if x.startswith('text/html'):
        # XXX
 #       print(r.http_text)
        print()


    elif x.startswith('application/json'):
        if options['print_json']:
            af_output = print_json(r.http_text, isjson=True)
            return af_output

        if options['print_python']:
            print_python(r.http_text, isjson=True)


def exit_for_http_status(r):
    if r.http_code is not None:
        if not (200 <= r.http_code < 300):
            sys.exit(1)
        else:
            return
    sys.exit(1)


def print_json(obj, isjson=False):
    if isjson:
        try:
            obj = json.loads(obj)
        except ValueError as e:
            print(e, file=sys.stderr)
            print(obj, file=sys.stderr)
            sys.exit(1)

 #   print(json.dumps(obj, sort_keys=True, indent=4,
 #                    separators=(',', ': ')))

    af_output = json.dumps(obj, sort_keys=True, indent=4,
                     separators=(',', ': '))

    return af_output


def process_arg(s, list=False):
    stdin_char = '-'

    if s == stdin_char:
        lines = sys.stdin.readlines()
    else:
        try:
            f = open(s)
            lines = f.readlines()
            f.close()
        except IOError:
            lines = [s]

    if debug > 1:
        print('lines:', lines, file=sys.stderr)

    if list:
        l = [x.rstrip('\r\n') for x in lines]
        return l

    lines = ''.join(lines)
    return lines

if __name__ == '__main__':
    panafapi_hacked()