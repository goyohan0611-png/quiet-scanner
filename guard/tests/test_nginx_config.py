import importlib.util
import pathlib
import unittest

path=pathlib.Path(__file__).resolve().parents[1]/'scripts/nginx_config.py'
spec=importlib.util.spec_from_file_location('nginx_config',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class CoverageTests(unittest.TestCase):
    def plan(self,extra='',location='location / { proxy_pass http://127.0.0.1:18081; }'):
        source='http { server { listen 8080; server_name guard.test; '+extra+location+' } }'
        inv={'nodes':module.nginx_parse(source,'/etc/nginx/site'),'texts':{'/etc/nginx/site':source}}
        return inv,module.nginx_plan(inv,['http://guard.test:8080'])

    def test_patch_preserves_quoted_json_and_checks_all_locations(self):
        inv,plan=self.plan(location='location / { proxy_pass http://127.0.0.1:18081; } location /api/ { add_header X-JSON \'{"a":1}\'; proxy_pass http://127.0.0.1:18081; }')
        self.assertEqual(len(plan['targets']),2)
        patched=module.nginx_patched(inv,plan)['/etc/nginx/site'].decode()
        self.assertIn('\'{"a":1}\'',patched)
        module.nginx_parse(patched)

    def test_refuses_coverage_bypass_proxy_and_local_error_handlers(self):
        for extra in ['real_ip_header X-Forwarded-For;','error_page 403 =200 /error;','access_by_lua_block { }','return 200 "ok";','rewrite / /index last;']:
            with self.subTest(extra=extra),self.assertRaises(ValueError):self.plan(extra)
        for loc in ['location ~ \\.php$ { fastcgi_pass 127.0.0.1:9000; }','location @app { proxy_pass http://127.0.0.1; }','location / { location /inner { } }']:
            with self.subTest(loc=loc),self.assertRaises(ValueError):self.plan(location=loc)

    def test_refuses_missing_alias_origin_and_recursive_syntax(self):
        with self.assertRaises(ValueError):self.plan('server_name other.test;')
        with self.assertRaises(ValueError):module.nginx_parse('http {'*40)


if __name__=='__main__':unittest.main()
