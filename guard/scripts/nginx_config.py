"""Read-only bounded Nginx parser for the initial Ubuntu package deployment.

This deliberately rejects constructs whose request coverage cannot be established.
It preserves source offsets so setup can add markers without reformatting files.
"""
import glob
import hashlib
import json
import os
import pathlib
import re
import stat
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class NginxNode:
    name: str
    args: list
    start: int
    end: int
    opening: int = 0
    children: list = field(default_factory=list)
    path: str = ''


def nginx_tokens(text):
    tokens = []
    pos = 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        if text[pos] == '#':
            pos = text.find('\n', pos)
            if pos < 0: break
            continue
        start = pos
        if text[pos] in '{};':
            tokens.append((text[pos], pos, pos + 1, True));pos += 1;continue
        word = ''
        quote = None
        while pos < len(text):
            char = text[pos]
            if quote:
                if char == quote: quote = None;pos += 1;continue
            else:
                if char in '\"\'': quote = char;pos += 1;continue
                if char.isspace() or char in '{};#': break
            if char == '\\' and pos + 1 < len(text):
                word += text[pos:pos + 2];pos += 2;continue
            if char == '$' and pos + 1 < len(text) and text[pos + 1] == '{':
                end = text.find('}', pos + 2)
                if end < 0: raise ValueError('Unclosed Nginx variable')
                word += text[pos:end + 1];pos = end + 1;continue
            word += char;pos += 1
        if quote: raise ValueError('Unclosed Nginx string')
        if pos == start: raise ValueError('Invalid Nginx token')
        tokens.append((word, start, pos, False))
        if len(tokens) > 50000: raise ValueError('Nginx configuration is too large')
    return tokens


def nginx_parse(text, path=''):
    tokens = nginx_tokens(text)
    index = 0
    def block(depth=0, nested=False):
        nonlocal index
        if depth > 32: raise ValueError('Nginx blocks are too deeply nested')
        nodes = []
        while index < len(tokens):
            token, start, _, symbol = tokens[index]
            if symbol and token == '}':
                if not nested: raise ValueError('Unexpected Nginx closing brace')
                index += 1;return nodes
            if symbol and token in '{;': raise ValueError('Unexpected Nginx delimiter')
            name = token;args = [];index += 1
            while index < len(tokens) and not tokens[index][3]:
                args.append(tokens[index][0]);index += 1
            if index >= len(tokens): raise ValueError('Incomplete Nginx directive')
            ending, _, end, _ = tokens[index];index += 1
            if ending == '}': raise ValueError('Incomplete Nginx directive')
            opening = end if ending == '{' else 0
            children = block(depth + 1, True) if opening else []
            nodes.append(NginxNode(name, args, start, tokens[index - 1][2], opening, children, path))
        if nested: raise ValueError('Unclosed Nginx block')
        return nodes
    return block()


def nginx_read(path, limit=4 * 1024 * 1024):
    path = pathlib.Path(path).resolve(strict=True)
    allowed = [pathlib.Path('/etc/nginx'), pathlib.Path('/usr/share/nginx/modules-available')]
    if not any(path.is_relative_to(root) for root in allowed):
        raise ValueError('Unsupported Nginx include outside package configuration directories: ' + str(path))
    for parent in path.parents:
        meta = parent.stat()
        if meta.st_uid != 0 or meta.st_mode & 0o022:
            raise ValueError('Writable or unowned Nginx configuration parent: ' + str(parent))
    with open(path, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022 or meta.st_size > limit:
            raise ValueError('Untrusted Nginx configuration: ' + str(path))
        raw = stream.read(limit + 1)
        if len(raw) > limit: raise ValueError('Nginx configuration exceeds limit')
    return path, raw, meta


def nginx_inventory():
    files = {};raws = {};metas = {}
    def expand(path, stack=()):
        path, raw, meta = nginx_read(path)
        if path in stack or len(stack) > 24: raise ValueError('Recursive Nginx include')
        if len(files) > 256: raise ValueError('Too many Nginx configuration files')
        files[str(path)] = hashlib.sha256(raw).hexdigest();raws[str(path)] = raw.decode('utf-8');metas[str(path)] = meta
        def walk(nodes):
            result = []
            for node in nodes:
                if node.name == 'include':
                    if len(node.args) != 1 or '$' in node.args[0]: raise ValueError('Unsupported dynamic Nginx include')
                    pattern = pathlib.Path(node.args[0])
                    if not pattern.is_absolute(): pattern = pathlib.Path('/etc/nginx') / pattern
                    matches = sorted(glob.glob(str(pattern)))
                    if not matches and not any(c in str(pattern) for c in '*?['): raise ValueError('Missing Nginx include')
                    for child in matches: result.extend(expand(child, (*stack, path)))
                else:
                    node.children = walk(node.children);result.append(node)
            return result
        return walk(nginx_parse(raws[str(path)], str(path)))
    nodes = expand('/etc/nginx/nginx.conf')
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'nodes': nodes, 'files': files, 'texts': raws, 'metas': metas, 'digest': digest}


def nginx_walk(nodes):
    for node in nodes:
        yield node
        yield from nginx_walk(node.children)


def nginx_plan(inventory, base_urls):
    http = [node for node in inventory['nodes'] if node.name == 'http']
    if len(http) != 1: raise ValueError('Exactly one Nginx http block is required')
    for node in nginx_walk(http):
        if '_by_lua' in node.name or node.name in {'lua_package_path', 'set_real_ip_from', 'real_ip_header', 'real_ip_recursive', 'proxy_protocol'}:
            raise ValueError('Existing Lua or real-IP handling requires a separate integration: ' + node.path)
        if node.name == 'error_page' and '403' in node.args:
            raise ValueError('An error_page handler intercepts WAF 403 responses: ' + node.path)
        if node.name == 'recursive_error_pages' and node.args != ['off']:
            raise ValueError('Recursive error pages require a separate integration')
    bases = []
    for value in base_urls:
        parsed = urlsplit(value)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {'', '/'}:
            raise ValueError('Site must be an HTTP(S) origin without credentials, query or path')
        bases.append({'url': value.rstrip('/'), 'host': parsed.hostname.lower(), 'port': parsed.port or (443 if parsed.scheme == 'https' else 80), 'tls': parsed.scheme == 'https'})
    if not bases: raise ValueError('At least one --site origin is required')
    scopes = [];servers = [];edits = {};targets = [];seen = set()
    for server in (n for n in http[0].children if n.name == 'server'):
        names = [arg.lower() for n in server.children if n.name == 'server_name' for arg in n.args] or ['_']
        if any(not re.fullmatch(r'[a-zA-Z0-9_.:-]+', name) for name in names): raise ValueError('Regex/wildcard server names are not in the first supported deployment')
        listens = []
        for n in (n for n in server.children if n.name == 'listen'):
            if any(x in n.args for x in ['proxy_protocol', 'quic']): raise ValueError('Proxy protocol and HTTP/3 require another deployment profile')
            value = n.args[0]
            if value.startswith('unix:'): raise ValueError('Existing Unix application listeners need a separate integration')
            port = int(value.rsplit(':', 1)[-1]) if ':' in value else int(value)
            pair = (port, 'ssl' in n.args)
            if pair not in listens: listens.append(pair)
        if not listens: listens = [(80, False)]
        nested = list(nginx_walk(server.children))
        redirects = [n for n in nested if n.name == 'return']
        redirect_only = bool(redirects) and not any(n.name in {'location', 'proxy_pass', 'fastcgi_pass', 'root', 'alias'} for n in server.children) and all(n.args and n.args[0] in {'301','302','307','308'} for n in redirects)
        if redirects and not redirect_only: raise ValueError('Rewrite-phase return bypasses access inspection: ' + server.path)
        if any(n.name in {'rewrite', 'if', 'grpc_pass'} for n in nested) and not redirect_only:
            raise ValueError('Rewrite/conditional/gRPC request paths require an explicitly tested integration: ' + server.path)
        locations = [n for n in server.children if n.name == 'location']
        for location in locations:
            if not location.args or location.args[0] in {'~','~*'} or location.args[-1].startswith('@') or any(n.name=='location' for n in nginx_walk(location.children)):
                raise ValueError('Regex, named or nested locations are outside the first deployment profile')
        coverage = [] if redirect_only else locations.copy()
        if not redirect_only and not any(n.args == ['/'] or n.args == ['^~','/'] for n in locations): coverage.append(server)
        server_scope = 'qg_' + hashlib.sha256((server.path + ':' + str(server.opening)).encode()).hexdigest()[:16]
        for node in [server, *locations]:
            identity = 'qg_' + hashlib.sha256((node.path + ':' + str(node.opening)).encode()).hexdigest()[:16]
            key = (node.path, node.opening)
            if key in seen: raise ValueError('A shared server/location include needs a separate integration')
            seen.add(key)
            if not pathlib.Path(node.path).is_relative_to('/etc/nginx'): raise ValueError('Only /etc/nginx site files may be changed')
            edits.setdefault(node.path, []).append((node.opening, '\n    # Quiet Guard scope ' + identity + '\n    set $quiet_guard_scope_id ' + identity + ';\n'))
            scopes.append({'id': identity, 'redirect_only': redirect_only})
            if node not in coverage: continue
            internal = any(n.name == 'internal' for n in node.children)
            if internal: continue
            if node.name == 'server': route = '/__quiet_guard_probe__'
            elif node.args[0] == '=': route = node.args[-1]
            else: route = node.args[-1].rstrip('/') + '/__quiet_guard_probe__'
            if not route.startswith('/') or not re.fullmatch(r'/[a-zA-Z0-9_./%-]*', route): raise ValueError('Cannot safely probe a configured location')
            for port,tls in listens:
                candidates = [base for base in bases if base['port']==port and base['tls']==tls and (base['host'] in names or '_' in names)]
                if not candidates: raise ValueError('Supply a --site origin for every serving server/port: ' + ','.join(names) + ':'+str(port))
                for name in names:
                    if name != '_' and not any(base['host']==name for base in candidates): raise ValueError('Supply a --site origin for each server alias: '+name)
                for base in candidates:
                    target_id = identity + '_' + hashlib.sha256((base['host']+':'+str(port)).encode()).hexdigest()[:12]
                    targets.append({'id':target_id,'scope':identity,'url':base['url']+route,'host':base['host'],'port':port,'path':route})
        servers.append({'scope':server_scope,'names':names,'listeners':listens,'redirect_only':redirect_only})
    if not targets or len(targets)>128: raise ValueError('Need 1..128 externally verifiable routes')
    return {'scopes':scopes,'servers':servers,'targets':targets,'edits':edits}


def nginx_patched(inventory, plan):
    result = {}
    for path, edits in plan['edits'].items():
        text = inventory['texts'][path]
        for position, addition in sorted(edits, reverse=True): text = text[:position] + addition + text[position:]
        result[path] = text.encode('utf-8')
    return result
