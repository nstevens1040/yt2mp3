import ffmpeg
import requests
import sys
import re
from xml.dom.minidom import parseString
import lxml.html
import json
import codecs
from urllib.parse import unquote
import wget
import base64
import binascii
import collections
import ctypes
import email
import getpass
import io
import itertools
import optparse
import os
import platform
import shlex
import shutil
import socket
import struct
import subprocess
import xml.etree.ElementTree
import youtube_dl
import operator
import traceback
import urllib.request as compat_urllib_request
import urllib.error as compat_urllib_error
import urllib.parse as compat_urllib_parse
from urllib.parse import urlparse as compat_urllib_parse_urlparse
import urllib.parse as compat_urlparse
import urllib.response as compat_urllib_response
import http.cookiejar as compat_cookiejar
compat_cookiejar_Cookie = compat_cookiejar.Cookie
import http.cookies as compat_cookies
import html.entities as compat_html_entities
compat_html_entities_html5 = compat_html_entities.html5
import http.client as compat_http_client
from urllib.error import HTTPError as compat_HTTPError
from urllib.request import urlretrieve as compat_urlretrieve
from html.parser import HTMLParser as compat_HTMLParser

ytvideolink=sys.argv[1]
ytvideolink = ytvideolink + "&gl=US&hl=en&has_verified=1&bpctr=9999999999"
def cls():
    import os
    os.system('cls')

def split_to_dict(instring):
    d = {}
    for i in instring.split('&'):
        k = i.split('=')[0]
        va = []
        for a in range(1,len(i.split('='))):
            va.append(i.split('=')[a])
        v = '='.join(va)
        d[k] = v
    return d

#ytvideolink = "https://www.youtube.com/watch?v=EZW7et3tPuQ&gl=US&hl=en&has_verified=1&bpctr=9999999999"
r = requests.get(ytvideolink)
document = lxml.html.fromstring(str(r.content))
childrens = document.getchildren()
for i in childrens:
    if i.tag == 'script':
        m=re.search('responseContext',i.text_content())
        if not m == None:
            if not m.span()[0] == 0:
                elem = i
                text_content = elem.text_content()
                if len(text_content) > 1000:
                    ytjson_string = re.search('(\{.*\})', text_content).groups()[0]
                    yt_unescape = codecs.decode(ytjson_string,'unicode_escape')
                    ytjson = json.loads(yt_unescape)
                    break

af= ytjson['streamingData']['adaptiveFormats']
af_audio = []
for i in af:
    if not i['mimeType'].find('audio') == -1:
        af_audio.append(i)

af_sorted = sorted(af_audio, key=lambda d: d['bitrate'])
ind = len(af_sorted) - 1
sel = af_sorted[ind]

kra = []
for i in sel.keys():
    kra.append(i)

if not 'url' in kra:
    sc = sel['signatureCipher']
    di = split_to_dict(sc)
    sig_ = unquote(di['s'])
    video_id_ = ytjson['videoDetails']['videoId']

for i in childrens:
    if i.tag == 'script':
        attrs = []
        for a in i.keys():
            attrs.append(a)
        if 'src' in attrs:
            src = i.values()[attrs.index('src')]
            m2=re.search('^http',src)
            if m2 == None:
                player_uri = src

url = unquote(di['url'])


class YoutubeDLError(Exception):
    pass
class compat_HTMLParseError(Exception):
    pass
from subprocess import DEVNULL
compat_subprocess_get_DEVNULL = lambda: DEVNULL
import http.server as compat_http_server
compat_str = str
from urllib.parse import unquote_to_bytes as compat_urllib_parse_unquote_to_bytes
from urllib.parse import unquote as compat_urllib_parse_unquote
from urllib.parse import unquote_plus as compat_urllib_parse_unquote_plus
_player_cache = {}
_code_cache = {}
compat_chr = chr
NO_DEFAULT = object()
compiled_regex_type = type(re.compile(''))
_downloader = youtube_dl.YoutubeDL()
compat_os_name = os._name if os.name == 'java' else os.name
_OPERATORS = [
    ('|', operator.or_),
    ('^', operator.xor),
    ('&', operator.and_),
    ('>>', operator.rshift),
    ('<<', operator.lshift),
    ('-', operator.sub),
    ('+', operator.add),
    ('%', operator.mod),
    ('/', operator.truediv),
    ('*', operator.mul),
]
_ASSIGN_OPERATORS = [(op + '=', opfunc) for op, opfunc in _OPERATORS]
_ASSIGN_OPERATORS.append(('=', lambda cur, right: right))
_NAME_RE = r'[a-zA-Z_$][a-zA-Z_$0-9]*'
_x_forwarded_for_ip = False
_PLAYER_INFO_RE = (
    r'/s/player/(?P<id>[a-zA-Z0-9_-]{8,})/player',
    r'/(?P<id>[a-zA-Z0-9_-]{8,})/player(?:_ias\.vflset(?:/[a-zA-Z]{2,3}_[a-zA-Z]{2,3})?|-plasma-ias-(?:phone|tablet)-[a-z]{2}_[A-Z]{2}\.vflset)/base\.js$',
    r'\b(?P<id>vfl[a-zA-Z0-9_-]+)\b.*?\.js$',
)
def _extract_signature_function(video_id, player_url, example_sig):
    player_id = _extract_player_info(player_url)
    func_id = 'js_%s_%s' % (
        player_id, _signature_cache_id(example_sig))
    assert os.path.basename(func_id) == func_id
    cache_spec = _downloader.cache.load('youtube-sigfuncs', func_id)
    if cache_spec is not None:
        return lambda s: ''.join(s[i] for i in cache_spec)
    if player_id not in _code_cache:
        _code_cache[player_id] = _download_webpage(
            player_url, video_id)
    code = _code_cache[player_id]
    res = _parse_sig_js(code)
    test_string = ''.join(map(compat_chr, range(len(example_sig))))
    cache_res = res(test_string)
    cache_spec = [ord(c) for c in cache_res]
    _downloader.cache.store('youtube-sigfuncs', func_id, cache_spec)
    return res
def _webpage_read_content(urlh, url_or_request, video_id, note=None, errnote=None, fatal=True, prefix=None, encoding=None):
    content_type = urlh.headers.get('Content-Type', '')
    webpage_bytes = urlh.read()
    if prefix is not None:
        webpage_bytes = prefix + webpage_bytes
    if not encoding:
        encoding = _guess_encoding_from_content(content_type, webpage_bytes)
    if _downloader.params.get('dump_intermediate_pages', False):
        print('Dumping request to ' + urlh.geturl())
        dump = base64.b64encode(webpage_bytes).decode('ascii')
        _downloader.print(dump)
    if _downloader.params.get('write_pages', False):
        basen = '%s_%s' % (video_id, urlh.geturl())
        if len(basen) > 240:
            h = '___' + hashlib.md5(basen.encode('utf-8')).hexdigest()
            basen = basen[:240 - len(h)] + h
        raw_filename = basen + '.dump'
        filename = sanitize_filename(raw_filename, restricted=True)
        print('Saving request to ' + filename)
        if compat_os_name == 'nt':
            absfilepath = os.path.abspath(filename)
            if len(absfilepath) > 259:
                filename = '\\\\?\\' + absfilepath
        with open(filename, 'wb') as outf:
            outf.write(webpage_bytes)
    try:
        content = webpage_bytes.decode(encoding, 'replace')
    except LookupError:
        content = webpage_bytes.decode('utf-8', 'replace')
    return content
def _decrypt_signature(s, video_id, player_url):
    if player_url is None:
        raise ExtractorError('Cannot decrypt signature without player_url')
    if player_url.startswith('//'):
        player_url = 'https:' + player_url
    elif not re.match(r'https?://', player_url):
        player_url = compat_urlparse.urljoin(
            'https://www.youtube.com', player_url)
    try:
        player_id = (player_url, _signature_cache_id(s))
        if player_id not in _player_cache:
            func = _extract_signature_function(
                video_id, player_url, s
            )
            _player_cache[player_id] = func
        func = _player_cache[player_id]
        if _downloader.params.get('youtube_print_sig_code'):
            _print_sig_code(func, s)
        return func(s)
    except Exception as e:
        tb = traceback.format_exc()
        raise ExtractorError(
            'Signature extraction failed: ' + tb, cause=e)
def _extract_player_info(player_url):
    for player_re in _PLAYER_INFO_RE:
        id_m = re.search(player_re, player_url)
        if id_m:
            break
    else:
        raise ExtractorError('Cannot identify player %r' % player_url)
    return id_m.group('id')
def _search_regex(pattern, string, name, default=NO_DEFAULT, fatal=True, flags=0, group=None):
    if isinstance(pattern, (str, compat_str, compiled_regex_type)):
        mobj = re.search(pattern, string, flags)
    else:
        for p in pattern:
            mobj = re.search(p, string, flags)
            if mobj:
                break
    if not _downloader.params.get('no_color') and compat_os_name != 'nt' and sys.stderr.isatty():
        _name = '\033[0;34m%s\033[0m' % name
    else:
        _name = name
    if mobj:
        if group is None:
            return next(g for g in mobj.groups() if g is not None)
        else:
            return mobj.group(group)
    elif default is not NO_DEFAULT:
        return default
    elif fatal:
        raise RegexNotFoundError('Unable to extract %s' % _name)
    else:
        _downloader.report_warning('unable to extract %s' % _name + bug_reports_message())
        return None
def _parse_sig_js(jscode):
    funcname = _search_regex(
        (r'\b[cs]\s*&&\s*[adf]\.set\([^,]+\s*,\s*encodeURIComponent\s*\(\s*(?P<sig>[a-zA-Z0-9$]+)\(',
         r'\b[a-zA-Z0-9]+\s*&&\s*[a-zA-Z0-9]+\.set\([^,]+\s*,\s*encodeURIComponent\s*\(\s*(?P<sig>[a-zA-Z0-9$]+)\(',
         r'\bm=(?P<sig>[a-zA-Z0-9$]{2})\(decodeURIComponent\(h\.s\)\)',
         r'\bc&&\(c=(?P<sig>[a-zA-Z0-9$]{2})\(decodeURIComponent\(c\)\)',
         r'(?:\b|[^a-zA-Z0-9$])(?P<sig>[a-zA-Z0-9$]{2})\s*=\s*function\(\s*a\s*\)\s*{\s*a\s*=\s*a\.split\(\s*""\s*\);[a-zA-Z0-9$]{2}\.[a-zA-Z0-9$]{2}\(a,\d+\)',
         r'(?:\b|[^a-zA-Z0-9$])(?P<sig>[a-zA-Z0-9$]{2})\s*=\s*function\(\s*a\s*\)\s*{\s*a\s*=\s*a\.split\(\s*""\s*\)',
         r'(?P<sig>[a-zA-Z0-9$]+)\s*=\s*function\(\s*a\s*\)\s*{\s*a\s*=\s*a\.split\(\s*""\s*\)',
r'([""\'])signature\1\s*,\s*(?P<sig>[a-zA-Z0-9$]+)\('
         r'\.sig\|\|(?P<sig>[a-zA-Z0-9$]+)\(',
         r'yt\.akamaized\.net/\)\s*\|\|\s*.*?\s*[cs]\s*&&\s*[adf]\.set\([^,]+\s*,\s*(?:encodeURIComponent\s*\()?\s*(?P<sig>[a-zA-Z0-9$]+)\(',
         r'\b[cs]\s*&&\s*[adf]\.set\([^,]+\s*,\s*(?P<sig>[a-zA-Z0-9$]+)\(',
         r'\b[a-zA-Z0-9]+\s*&&\s*[a-zA-Z0-9]+\.set\([^,]+\s*,\s*(?P<sig>[a-zA-Z0-9$]+)\(',
         r'\bc\s*&&\s*a\.set\([^,]+\s*,\s*\([^)]*\)\s*\(\s*(?P<sig>[a-zA-Z0-9$]+)\(',
         r'\bc\s*&&\s*[a-zA-Z0-9]+\.set\([^,]+\s*,\s*\([^)]*\)\s*\(\s*(?P<sig>[a-zA-Z0-9$]+)\(',
         r'\bc\s*&&\s*[a-zA-Z0-9]+\.set\([^,]+\s*,\s*\([^)]*\)\s*\(\s*(?P<sig>[a-zA-Z0-9$]+)\('),
        jscode, 'Initial JS player signature function name', group='sig')
    jsi = JSInterpreter(jscode)
    initial_function = jsi.extract_function(funcname)
    return lambda s: initial_function([s])
def _print_sig_code(func, example_sig):
    def gen_sig_code(idxs):
        def _genslice(start, end, step):
            starts = '' if start == 0 else str(start)
            ends = (':%d' % (end + step)) if end + step >= 0 else ':'
            steps = '' if step == 1 else (':%d' % step)
            return 's[%s%s%s]' % (starts, ends, steps)
        step = None
        start = '(Never used)'
        for i, prev in zip(idxs[1:], idxs[:-1]):
            if step is not None:
                if i - prev == step:
                    continue
                yield _genslice(start, prev, step)
                step = None
                continue
            if i - prev in [-1, 1]:
                step = i - prev
                start = prev
                continue
            else:
                yield 's[%d]' % prev
        if step is None:
            yield 's[%d]' % i
        else:
            yield _genslice(start, i, step)
    test_string = ''.join(map(compat_chr, range(len(example_sig))))
    cache_res = func(test_string)
    cache_spec = [ord(c) for c in cache_res]
    expr_code = ' + '.join(gen_sig_code(cache_spec))
    signature_id_tuple = '(%s)' % (
        ', '.join(compat_str(len(p)) for p in example_sig.split('.')))
    code = ('if tuple(len(p) for p in s.split(\'.\')) == %s:\n'
            '    return %s\n') % (signature_id_tuple, expr_code)
    print('Extracted signature function:\n' + code)
def _request_webpage(url_or_request, video_id, note=None, errnote=None, fatal=True, data=None, headers={}, query={}, expected_status=None):
    if note is not False:
        if video_id is None:
            print('%s' % (note,))
        else:
            print('%s: %s' % (video_id, note))
    if _x_forwarded_for_ip:
        if 'X-Forwarded-For' not in headers:
            headers['X-Forwarded-For'] = _x_forwarded_for_ip
    if isinstance(url_or_request, compat_urllib_request.Request):
        url_or_request = update_Request(
            url_or_request, data=data, headers=headers, query=query)
    else:
        if query:
            url_or_request = update_url_query(url_or_request, query)
        if data is not None or headers:
            url_or_request = sanitized_Request(url_or_request, data, headers)
    exceptions = [compat_urllib_error.URLError, compat_http_client.HTTPException, socket.error]

    try:
        return _downloader.urlopen(url_or_request)
    except tuple(exceptions) as err:
        if isinstance(err, compat_urllib_error.HTTPError):
            if __can_accept_status_code(err, expected_status):
                err.fp._error = err
                return err.fp
        if errnote is False:
            return False
        if errnote is None:
            errnote = 'Unable to download webpage'
        errmsg = '%s: %s' % (errnote, error_to_compat_str(err))
        if fatal:
            raise ExtractorError(errmsg, sys.exc_info()[2], cause=err)
        else:
            _downloader.report_warning(errmsg)
            return False
def _signature_cache_id(example_sig):
    return '.'.join(compat_str(len(part)) for part in example_sig.split('.'))
def compat_parse_qs(qs, keep_blank_values=False, strict_parsing=False,
                    encoding='utf-8', errors='replace'):
    parsed_result = {}
    pairs = _parse_qsl(qs, keep_blank_values, strict_parsing,
                       encoding=encoding, errors=errors)
    for name, value in pairs:
        if name in parsed_result:
            parsed_result[name].append(value)
        else:
            parsed_result[name] = [value]
    return parsed_result
def _download_webpage_handle(url_or_request, video_id, note=None, errnote=None, fatal=True, encoding=None, data=None, headers={}, query={}, expected_status=None):
    if isinstance(url_or_request, (compat_str, str)):
        url_or_request = url_or_request.partition('#')[0]
    urlh = _request_webpage(url_or_request, video_id, note, errnote, fatal, data=data, headers=headers, query=query, expected_status=expected_status)
    if urlh is False:
        assert not fatal
        return False
    content = _webpage_read_content(urlh, url_or_request, video_id, note, errnote, fatal, encoding=encoding)
    return (content, urlh)
def remove_quotes(s):
    if s is None or len(s) < 2:
        return s
    for quote in ('""', "'", ):
        if s[0] == quote and s[-1] == quote:
            return s[1:-1]
    return s
def _parse_qsl(qs, keep_blank_values=False, strict_parsing=False,
               encoding='utf-8', errors='replace'):
    qs, _coerce_result = qs, compat_str
    pairs = [s2 for s1 in qs.split('&') for s2 in s1.split(';')]
    r = []
    for name_value in pairs:
        if not name_value and not strict_parsing:
            continue
        nv = name_value.split('=', 1)
        if len(nv) != 2:
            if strict_parsing:
                raise ValueError('bad query field: %r' % (name_value,))
            if keep_blank_values:
                nv.append('')
            else:
                continue
        if len(nv[1]) or keep_blank_values:
            name = nv[0].replace('+', ' ')
            name = compat_urllib_parse_unquote(
                name, encoding=encoding, errors=errors)
            name = _coerce_result(name)
            value = nv[1].replace('+', ' ')
            value = compat_urllib_parse_unquote(
                value, encoding=encoding, errors=errors)
            value = _coerce_result(value)
            r.append((name, value))
    return r
def _guess_encoding_from_content(content_type, webpage_bytes):
    m = re.match(r'[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+\s*;\s*charset=(.+)', content_type)
    if m:
        encoding = m.group(1)
    else:
        m = re.search(br'<meta[^>]+charset=[\'""]?([^\'"")]+)[ /\'"">]',
                      webpage_bytes[:1024])
        if m:
            encoding = m.group(1).decode('ascii')
        elif webpage_bytes.startswith(b'\xff\xfe'):
            encoding = 'utf-16'
        else:
            encoding = 'utf-8'
    return encoding
def _download_webpage(
        url_or_request, video_id, note=None, errnote=None,
        fatal=True, tries=1, timeout=5, encoding=None, data=None,
        headers={}, query={}, expected_status=None):
    success = False
    try_count = 0
    while success is False:
        try:
            res = _download_webpage_handle(
                url_or_request, video_id, note, errnote, fatal,
                encoding=encoding, data=data, headers=headers, query=query,
                expected_status=expected_status)
            success = True
        except compat_http_client.IncompleteRead as e:
            try_count += 1
            if try_count >= tries:
                raise e
            _sleep(timeout, video_id)
    if res is False:
        return res
    else:
        content, _ = res
        return content
class JSInterpreter(object):
    def __init__(self, code, objects=None):
        if objects is None:
            objects = {}
        self.code = code
        self._functions = {}
        self._objects = objects
    def interpret_statement(self, stmt, local_vars, allow_recursion=100):
        if allow_recursion < 0:
            raise ExtractorError('Recursion limit reached')
        should_abort = False
        stmt = stmt.lstrip()
        stmt_m = re.match(r'var\s', stmt)
        if stmt_m:
            expr = stmt[len(stmt_m.group(0)):]
        else:
            return_m = re.match(r'return(?:\s+|$)', stmt)
            if return_m:
                expr = stmt[len(return_m.group(0)):]
                should_abort = True
            else:
                # Try interpreting it as an expression
                expr = stmt
        v = self.interpret_expression(expr, local_vars, allow_recursion)
        return v, should_abort
    def interpret_expression(self, expr, local_vars, allow_recursion):
        expr = expr.strip()
        if expr == '':  # Empty expression
            return None
        if expr.startswith('('):
            parens_count = 0
            for m in re.finditer(r'[()]', expr):
                if m.group(0) == '(':
                    parens_count += 1
                else:
                    parens_count -= 1
                    if parens_count == 0:
                        sub_expr = expr[1:m.start()]
                        sub_result = self.interpret_expression(
                            sub_expr, local_vars, allow_recursion)
                        remaining_expr = expr[m.end():].strip()
                        if not remaining_expr:
                            return sub_result
                        else:
                            expr = json.dumps(sub_result) + remaining_expr
                        break
            else:
                raise ExtractorError('Premature end of parens in %r' % expr)
        for op, opfunc in _ASSIGN_OPERATORS:
            m = re.match(r'''(?x)
                (?P<out>%s)(?:\[(?P<index>[^\]]+?)\])?
                \s*%s
                (?P<expr>.*)$''' % (_NAME_RE, re.escape(op)), expr)
            if not m:
                continue
            right_val = self.interpret_expression(
                m.group('expr'), local_vars, allow_recursion - 1)
            if m.groupdict().get('index'):
                lvar = local_vars[m.group('out')]
                idx = self.interpret_expression(
                    m.group('index'), local_vars, allow_recursion)
                assert isinstance(idx, int)
                cur = lvar[idx]
                val = opfunc(cur, right_val)
                lvar[idx] = val
                return val
            else:
                cur = local_vars.get(m.group('out'))
                val = opfunc(cur, right_val)
                local_vars[m.group('out')] = val
                return val
        if expr.isdigit():
            return int(expr)
        var_m = re.match(
            r'(?!if|return|true|false)(?P<name>%s)$' % _NAME_RE,
            expr)
        if var_m:
            return local_vars[var_m.group('name')]
        try:
            return json.loads(expr)
        except ValueError:
            pass
        m = re.match(
            r'(?P<in>%s)\[(?P<idx>.+)\]$' % _NAME_RE, expr)
        if m:
            val = local_vars[m.group('in')]
            idx = self.interpret_expression(
                m.group('idx'), local_vars, allow_recursion - 1)
            return val[idx]
        m = re.match(
            r'(?P<var>%s)(?:\.(?P<member>[^(]+)|\[(?P<member2>[^]]+)\])\s*(?:\(+(?P<args>[^()]*)\))?$' % _NAME_RE,
            expr)
        if m:
            variable = m.group('var')
            member = remove_quotes(m.group('member') or m.group('member2'))
            arg_str = m.group('args')
            if variable in local_vars:
                obj = local_vars[variable]
            else:
                if variable not in self._objects:
                    self._objects[variable] = self.extract_object(variable)
                obj = self._objects[variable]
            if arg_str is None:
                # Member access
                if member == 'length':
                    return len(obj)
                return obj[member]
            assert expr.endswith(')')
            # Function call
            if arg_str == '':
                argvals = tuple()
            else:
                argvals = tuple([
                    self.interpret_expression(v, local_vars, allow_recursion)
                    for v in arg_str.split(',')])
            if member == 'split':
                assert argvals == ('',)
                return list(obj)
            if member == 'join':
                assert len(argvals) == 1
                return argvals[0].join(obj)
            if member == 'reverse':
                assert len(argvals) == 0
                obj.reverse()
                return obj
            if member == 'slice':
                assert len(argvals) == 1
                return obj[argvals[0]:]
            if member == 'splice':
                assert isinstance(obj, list)
                index, howMany = argvals
                res = []
                for i in range(index, min(index + howMany, len(obj))):
                    res.append(obj.pop(index))
                return res
            return obj[member](argvals)
        for op, opfunc in _OPERATORS:
            m = re.match(r'(?P<x>.+?)%s(?P<y>.+)' % re.escape(op), expr)
            if not m:
                continue
            x, abort = self.interpret_statement(
                m.group('x'), local_vars, allow_recursion - 1)
            if abort:
                raise ExtractorError(
                    'Premature left-side return of %s in %r' % (op, expr))
            y, abort = self.interpret_statement(
                m.group('y'), local_vars, allow_recursion - 1)
            if abort:
                raise ExtractorError(
                    'Premature right-side return of %s in %r' % (op, expr))
            return opfunc(x, y)
        m = re.match(
            r'^(?P<func>%s)\((?P<args>[a-zA-Z0-9_$,]*)\)$' % _NAME_RE, expr)
        if m:
            fname = m.group('func')
            argvals = tuple([
                int(v) if v.isdigit() else local_vars[v]
                for v in m.group('args').split(',')]) if len(m.group('args')) > 0 else tuple()
            if fname not in self._functions:
                self._functions[fname] = self.extract_function(fname)
            return self._functions[fname](argvals)
        raise ExtractorError('Unsupported JS expression %r' % expr)
    def extract_object(self, objname):
        _FUNC_NAME_RE = r'''(?:[a-zA-Z$0-9]+|"[a-zA-Z$0-9]+"|'[a-zA-Z$0-9]+')'''
        obj = {}
        obj_m = re.search(
            r'''(?x)
                (?<!this\.)%s\s*=\s*{\s*
                    (?P<fields>(%s\s*:\s*function\s*\(.*?\)\s*{.*?}(?:,\s*)?)*)
                }\s*;
            ''' % (re.escape(objname), _FUNC_NAME_RE),
            self.code)
        fields = obj_m.group('fields')
        # Currently, it only supports function definitions
        fields_m = re.finditer(
            r'''(?x)
                (?P<key>%s)\s*:\s*function\s*\((?P<args>[a-z,]+)\){(?P<code>[^}]+)}
            ''' % _FUNC_NAME_RE,
            fields)
        for f in fields_m:
            argnames = f.group('args').split(',')
            obj[remove_quotes(f.group('key'))] = self.build_function(argnames, f.group('code'))
        return obj
    def extract_function(self, funcname):
        func_m = re.search(
            r'''(?x)
                (?:function\s+%s|[{;,]\s*%s\s*=\s*function|var\s+%s\s*=\s*function)\s*
                \((?P<args>[^)]*)\)\s*
                \{(?P<code>[^}]+)\}''' % (
                re.escape(funcname), re.escape(funcname), re.escape(funcname)),
            self.code)
        if func_m is None:
            raise ExtractorError('Could not find JS function %r' % funcname)
        argnames = func_m.group('args').split(',')
        return self.build_function(argnames, func_m.group('code'))
    def call_function(self, funcname, *args):
        f = self.extract_function(funcname)
        return f(args)
    def build_function(self, argnames, code):
        def resf(args):
            local_vars = dict(zip(argnames, args))
            for stmt in code.split(';'):
                res, abort = self.interpret_statement(stmt, local_vars)
                if abort:
                    break
            return res
        return resf
class ExtractorError(YoutubeDLError):
    def __init__(self, msg, tb=None, expected=False, cause=None, video_id=None):
        if sys.exc_info()[0] in (compat_urllib_error.URLError, socket.timeout, UnavailableVideoError):
            expected = True
        if video_id is not None:
            msg = video_id + ': ' + msg
        if cause:
            msg += ' (caused by %r)' % cause
        if not expected:
            msg += bug_reports_message()
        super(ExtractorError, self).__init__(msg)
        self.traceback = tb
        self.exc_info = sys.exc_info()  # preserve original exception
        self.cause = cause
        self.video_id = video_id
    def format_traceback(self):
        if self.traceback is None:
            return None
        return ''.join(traceback.format_tb(self.traceback))


signature = _decrypt_signature(sig_,video_id_,player_uri)

audio_uri = url + "&sig=" + unquote(signature)
extension = sel['mimeType'].split('/')[1].split(';')[0]

illegal = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x22\x2a\x2f\x3a\x3c\x3e\x3f\x5c\x7c'
title_ra = []
for i in ytjson['videoDetails']['title']:
    if not i.encode() in illegal:
        title_ra.append(i)

filename = "".join(title_ra)
fullpath = os.path.realpath(os.path.curdir) + os.path.sep + filename + "." + extension
mp3_path = os.path.realpath(os.path.curdir) + os.path.sep + filename + ".mp3"
wget.download(audio_uri,fullpath)
prb = ffmpeg.probe(fullpath)
sample_rate = prb['streams'][0]['sample_rate']
bit_rate = prb['format']['bit_rate']
ffmpeg_output = []
try:
    ffmpeg_output = ffmpeg.run(
        ffmpeg.output(
            ffmpeg.input(fullpath),
            mp3_path,
            audio_bitrate=bit_rate,
            ar=sample_rate,
            acodec='libmp3lame'
        ),
        capture_stdout=True,
        capture_stderr=True,
        input=None,
        quiet=True,
        overwrite_output=True
    )
except:
    ERRCATCH = 1
    print(ffmpeg_output[1].decode())

os.remove(fullpath)
