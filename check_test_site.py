#!/usr/bin/env python3
"""可獨立攜帶到測試站儲存庫的發布前檢查；不連線。"""
import argparse
import hashlib
from html import unescape
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


class CheckError(ValueError):
    """不含命中原文的檢查失敗。"""


def need(condition, message):
    if not condition:
        raise CheckError(message)


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.nodes, self.stack = [], []
        self.first_element = None

    def handle_starttag(self, tag, attrs):
        node = {'tag': tag, 'attrs': dict(attrs), 'parents': list(self.stack), 'text': ''}
        need(len(attrs) == len(dict(attrs)), '頁面含重複屬性。')
        if self.first_element is None and any(n['tag'] == 'body' for n in self.stack):
            self.first_element = node
        self.nodes.append(node)
        if tag not in ('meta', 'link', 'img', 'br', 'hr', 'input', 'source'):
            self.stack.append(node)

    def handle_endtag(self, tag):
        need(self.stack and self.stack[-1]['tag'] == tag, '頁面結構無效。')
        self.stack.pop()

    def handle_data(self, value):
        for node in self.stack:
            node['text'] += value


def synthetic_name(value, kind):
    patterns = {'merchant': r'示範(?:烘焙坊|食材坊|冷凍坊) [A-C]（虛構）',
                'product': r'示範商品 [A-C][0-9]{2}（虛構）', 'store': r'示範門市 [A-C][0-9]{2}（虛構）',
                'consumer': r'測試消費者 [0-9]{3}'}
    return isinstance(value, str) and re.fullmatch(patterns[kind], value) is not None


def check(directory):
    root = Path(directory)
    need(root.is_dir() and not root.is_symlink(), '找不到測試站目錄。')
    paths = list(root.rglob('*'))
    need(not any(path.is_symlink() for path in paths), '測試站不可含符號連結。')
    blobs = {p.relative_to(root).as_posix(): p.read_bytes() for p in paths if p.is_file()}
    need('publish_manifest.json' in blobs and 'fixture_inventory.json' in blobs, '缺少發布紀錄或虛構身分清單。')
    manifest = json.loads(blobs['publish_manifest.json'])
    need(set(manifest) == {'files', 'generator_commit', 'template_version', 'fixtures_check', 'env', 'generator_source_sha256'}, '發布紀錄欄位不符。')
    need(manifest['env'] == 'test' and manifest['fixtures_check'] == 'passed'
         and re.fullmatch(r'[0-9a-f]{40}', manifest['generator_commit'])
         and re.fullmatch(r'[0-9a-f]{64}', manifest['generator_source_sha256'])
         and re.fullmatch(r'[a-z][a-z0-9_]{0,63}', manifest['template_version']), '發布紀錄無效。')
    need(set(blobs) == set(manifest['files']) | {'publish_manifest.json'}, '發布檔案清單不符。')
    for name, digest in manifest['files'].items():
        need(re.fullmatch(r'[0-9a-f]{64}', digest) and hashlib.sha256(blobs[name]).hexdigest() == digest, '發布產物摘要不符。')
    inventory = json.loads(blobs['fixture_inventory.json'])
    need(set(inventory) == {'merchants', 'products'}, '虛構清單欄位不符。')
    merchants, products = {}, {}
    for merchant in inventory['merchants']:
        need(set(merchant) == {'page_slug', 'name', 'stores'} and synthetic_name(merchant['name'], 'merchant')
             and re.fullmatch(r'fixture_merchant_[a-c]', merchant['page_slug']), '商家名稱不是核定虛構格式。')
        need(merchant['page_slug'] not in merchants, '商家代稱重複。')
        merchants[merchant['page_slug']] = merchant['name']
        for store in merchant['stores']:
            need(set(store) == {'name', 'address'} and synthetic_name(store['name'], 'store')
                 and re.fullmatch(r'虛構地址-M[A-C][0-9]{2}（不存在）', store['address']), '門市資料不是虛構格式。')
    for product in inventory['products']:
        need(set(product) == {'sku', 'name'} and synthetic_name(product['name'], 'product')
             and re.fullmatch(r'fixture_sku_[a-c]_[0-9]{2}', product['sku']), '商品名稱不是核定虛構格式。')
        need(product['sku'] not in products, '商品代號重複。')
        products[product['sku']] = product['name']
    need(merchants and products, '虛構清單不能是空白。')
    sensitive = re.compile(r'\b(?:sk_|gh[pousr]_)[A-Za-z0-9_-]{20,}|\bAKIA[A-Z0-9]{16}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}|(?:api[_-]?key|access[_-]?token|secret)\s*[=:]\s*["\x27]?[A-Za-z0-9_/-]{20,}', re.I)
    email = re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')
    phone = re.compile(r'(?<![A-Za-z0-9])(?:\+886|0[2-9])(?:[ _-]*[0-9]){7,9}(?![A-Za-z0-9])')
    addresses = re.compile(r'[\u4e00-\u9fff]{2,}(?:市|縣)(?:[\u4e00-\u9fff]+(?:區|鄉|鎮|市))?[\u4e00-\u9fff0-9]+(?:路|街)(?:[一二三四五六七八九十百0-9]+段)?')
    html_count = 0
    known_digests = set(manifest['files'].values()) | {manifest['generator_commit']}
    for name, blob in blobs.items():
        need(Path(name).suffix in ('.html', '.json', '.txt', '.xml'), '測試站出現未允許的檔案類型。')
        text = unescape(blob.decode('utf-8'))
        need(not sensitive.search(text), '疑似機密字串，停止打包。')
        scrubbed = text
        for digest in known_digests:
            scrubbed = scrubbed.replace(digest, '')
        scrubbed = re.sub(r'catalog_[a-f0-9]{64}', '', scrubbed)
        need(not addresses.search(scrubbed), '疑似路段地址，待查；禁止輸出或打包。')
        need(not email.search(scrubbed) and not phone.search(scrubbed), '出現非虛構聯絡資料。')
        need(not re.search(r'tel:|mailto:|\bBuyAction\b|\bPayAction\b|\bCheckoutAction\b', text, re.I), '測試站含聯絡或付款標記。')
        if name.endswith('.json'):
            data = json.loads(blob)
            def inspect(value, path=()):
                if isinstance(value, dict):
                    if 'payment_link' in value:
                        need(value['payment_link'] is None, '付款連結必須為空值。')
                    for key, child in value.items():
                        inspect(child, path + (key,))
                elif isinstance(value, list):
                    for child in value:
                        inspect(child, path)
                elif isinstance(value, str) and path:
                    field = path[-1]
                    if field in ('brand_display_name', 'brand_official_name', 'product_legal_manufacturer_name'):
                        need(value == '待法律評估' or synthetic_name(value, 'merchant'), '名稱不是虛構格式。')
                    if field == 'product_legal_name':
                        need(synthetic_name(value, 'product'), '商品名稱不是虛構格式。')
                    if field.endswith('phone'):
                        need(value == '待法律評估' or re.fullmatch(r'TEST-PHONE-[MC][A-C]?[0-9]{2,3}', value), '電話不是虛構格式。')
                    if field.endswith('address'):
                        need(value == '待法律評估' or re.fullmatch(r'虛構地址-[MC][A-C]?[0-9]{2,3}（不存在）', value), '地址不是虛構格式。')
            inspect(data)
        if not name.endswith('.html'):
            continue
        html_count += 1
        doc = Page(); doc.feed(blob.decode('utf-8')); doc.close()
        need(not doc.stack, '頁面標籤未閉合。')
        robots = [n for n in doc.nodes if n['tag'] == 'meta' and n['attrs'].get('name') == 'robots']
        need(len(robots) == 1 and robots[0]['attrs'].get('content') == 'noindex, nofollow'
             and any(p['tag'] == 'head' for p in robots[0]['parents']), '測試頁缺少禁止索引標記。')
        first = doc.first_element
        need(first is not None and first['attrs'].get('class') == 'test-banner'
             and first['text'] == '測試站，不受理訂單', '測試橫幅缺少或不在最上方。')
        for node in doc.nodes:
            tag, attrs = node['tag'], node['attrs']
            need(tag not in ('form', 'input', 'button', 'script', 'iframe', 'object', 'embed', 'base'), '測試站含互動表單或外部內容。')
            need(not any(k.startswith('on') for k in attrs), '測試站含可執行屬性。')
            need('data-action' not in attrs, '測試站不得接受訂購或詢價。')
            for key in ('href', 'src'):
                if key not in attrs or (tag == 'link' and attrs.get('rel') == 'canonical'):
                    continue
                need(attrs[key].startswith('/') and not attrs[key].startswith('//') and '..' not in attrs[key]
                     and '\\' not in attrs[key], '測試站不得載入外部內容或導流。')
            need(not re.search(r'url\s*\(|@import|expression\s*\(', (node['text'] if tag == 'style' else '') + attrs.get('style', ''), re.I), '測試站不得載入外部樣式或追蹤碼。')
            if attrs.get('data-allowed-brand') == 'true':
                need(synthetic_name(node['text'], 'merchant'), '商家顯示名稱不是虛構格式。')
            if attrs.get('data-field') == 'name':
                need(synthetic_name(node['text'], 'product'), '商品顯示名稱不是虛構格式。')
            if attrs.get('data-sku'):
                sku = attrs['data-sku']
                need(sku in products and node['text'].startswith(products[sku] + ' — '), '商品列表名稱與虛構清單不符。')
            if tag == 'h1' and name in {slug + '/index.html' for slug in merchants}:
                need(node['text'] == merchants[name.split('/')[0]], '商家首頁名稱與虛構清單不符。')
    need(html_count > 0 and blobs.get('robots.txt') == b'User-agent: *\nDisallow: /\n', '測試站缺頁面或全站禁止索引設定。')
    for name, blob in blobs.items():
        if name.endswith('.xml'):
            tree = ET.fromstring(blob)
            need(not any(element.tag.rsplit('}', 1)[-1] == 'loc' for element in tree.iter()), '測試站網站地圖不得列網址。')
    return {'files': len(blobs), 'html_pages': html_count, 'fixtures_check': 'passed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    args = parser.parse_args()
    try:
        result = check(args.directory)
        print(f"測試站發布前檢查通過：{result['html_pages']} 個頁面。")
        return 0
    except (CheckError, OSError, ValueError, TypeError, KeyError, ET.ParseError) as error:
        print(str(error) if isinstance(error, CheckError) else '測試站檔案或格式不符，停止打包。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
