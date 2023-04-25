import argparse
import asyncio
import aiohttp
import cchardet as chardet
import difflib
import re

from aiohttp import ClientTimeout, TooManyRedirects
from bs4 import BeautifulSoup
from termcolor import colored
from urllib.parse import urlparse, urljoin


def bandingkan_konten(konten1, konten2):
    differ = difflib.Differ()
    perbedaan = list(differ.compare(konten1.splitlines(), konten2.splitlines()))
    hitung_perbedaan = sum(1 for diff in perbedaan if diff[0] in ('+', '-'))
    return hitung_perbedaan


class DOVE:
    def __init__(self, login_url, max_redirects=10, max_timeout=10):
        self.login_url = login_url
        self.max_redirects = max_redirects
        self.max_timeout = max_timeout
        parsed_login_url = urlparse(login_url)
        self.scope = f"{parsed_login_url.scheme}://{parsed_login_url.netloc}"
        self.urls = set()
        self.visited_urls = set()
        self.session1 = None
        self.session2 = None

    async def buat_sesi(self):
        user_agent = 'Mozilla/5.0 (Windows) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
        self.session1 = aiohttp.ClientSession(
            headers={'User-Agent': user_agent},
            timeout=ClientTimeout(total=self.max_timeout)
        )
        self.session2 = aiohttp.ClientSession(
            headers={'User-Agent': user_agent},
            timeout=ClientTimeout(total=self.max_timeout)
        )

    async def tutup_sesi(self):
        await self.session1.close()
        await self.session2.close()

    async def masuk(self, nama_pengguna1, kata_sandi1, nama_pengguna2, kata_sandi2):
        token1 = await self._ambil_token(self.login_url, self.session1)
        token2 = await self._ambil_token(self.login_url, self.session2)

        payload1 = {'login': nama_pengguna1, 'password': kata_sandi1}
        payload2 = {'login': nama_pengguna2, 'password': kata_sandi2}

        if token1 or token2:
            gunakan_token = input("Token CSRF ditemukan. Apakah Anda ingin menggunakannya? (y/n): ")
            if gunakan_token.lower() == 'y':
                payload1['_token'] = token1
                payload2['_token'] = token2

        await self.session1.post(self.login_url, data=payload1)
        await self.session2.post(self.login_url, data=payload2)

    async def scan(self):
        await self._pindai_url(self.scope)

        while self.urls:
            tasks = [asyncio.ensure_future(self._pindai_url(self.urls.pop())) for _ in range(min(10, len(self.urls)))]
            await asyncio.gather(*tasks)

    @staticmethod
    async def _ambil_token(url, session):
        response = await session.get(url)
        content = await response.content.read()
        encoding = chardet.detect(content)['encoding']
        content = content.decode(encoding)
        soup = BeautifulSoup(content, 'html.parser')
        token_input = soup.find('input', {'name': '_token'})
        return token_input['value'] if token_input else None

    @staticmethod
    def _cek_id_di_url(url1, url2):
        regex = r"/\d+"
        id1 = re.search(regex, url1)
        id2 = re.search(regex, url2)
        return id1 is not None and id2 is not None and id1.group() == id2.group()

    @staticmethod
    def _cek_eksploit_query_param(url1, url2):
        parsed_url1 = urlparse(str(url1))
        parsed_url2 = urlparse(str(url2))
        return parsed_url1.path == parsed_url2.path and parsed_url1.query != parsed_url2.query

    @staticmethod
    async def _handle_respons(response1, response2, url):
        konten1 = await response1.content.read()
        konten2 = await response2.content.read()

        encoding1 = chardet.detect(konten1)['encoding'] or 'utf-8'
        encoding2 = chardet.detect(konten2)['encoding'] or 'utf-8'

        konten1 = konten1.decode(encoding1, errors='ignore')
        konten2 = konten2.decode(encoding2, errors='ignore')

        hitung_perbedaan = bandingkan_konten(konten1, konten2)

        # Sesuaikan nilai toleransi untuk menyesuaikan dengan konten yang berbeda
        toleransi = 5

        if response1.status != 404 and response2.status != 404 and (
            hitung_perbedaan <= toleransi or
            DOVE._cek_id_di_url(str(response1.url), str(response2.url)) or
            DOVE._cek_eksploit_query_param(response1.url, response2.url)
        ):
            print(colored(f'[RENTAN] {url}', 'red'))
        else:
            print(colored(f'[AMAN] {url}', 'green'))

        return konten1

    def _ekstrak_url_bersarang(self, content):
        soup = BeautifulSoup(content, 'html.parser')
        all_links = soup.find_all(href=True)
        for link in all_links:
            nested_url = link['href'].strip()
            if nested_url.startswith('/'):
                nested_url = urljoin(self.scope, nested_url)
            if nested_url.startswith(self.scope) and nested_url not in self.visited_urls:
                self.urls.add(nested_url)

    async def _pindai_url(self, url):
        if url in self.visited_urls:
            return

        self.visited_urls.add(url)

        try:
            async with self.session1.get(url, max_redirects=self.max_redirects) as response1, \
                    self.session2.get(url, max_redirects=self.max_redirects) as response2:
                konten1 = await self._handle_respons(response1, response2, url)
                self._ekstrak_url_bersarang(konten1)
        except (asyncio.TimeoutError, TooManyRedirects):
            pass

    async def jalankan(self, nama_pengguna1, kata_sandi1, nama_pengguna2, kata_sandi2):
        try:
            await self.buat_sesi()
            await self.masuk(nama_pengguna1, kata_sandi1, nama_pengguna2, kata_sandi2)
            await self.scan()
        except RuntimeError as e:
            if isinstance(e, RuntimeError) and str(e) == 'Event loop is closed':
                asyncio.set_event_loop(asyncio.new_event_loop())
                loop = asyncio.get_event_loop()
                loop.run_until_complete(self.jalankan(nama_pengguna1, kata_sandi1, nama_pengguna2, kata_sandi2))
            else:
                raise e
        finally:
            await self.tutup_sesi()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DOVE - Direct Object Vulnerability Evaluator')
    parser.add_argument('-u', '--url', help='URL login', required=True)
    parser.add_argument('-u1', '--usr1', help='Nama pengguna untuk akun 1', required=True)
    parser.add_argument('-p1', '--pwd1', help='Kata sandi untuk akun 1', required=True)
    parser.add_argument('-u2', '--usr2', help='Nama pengguna untuk akun 2', required=True)
    parser.add_argument('-p2', '--pwd2', help='Kata sandi untuk akun 2', required=True)
    parser.add_argument('-r', '--redirects', help='Jumlah maksimum pengalihan', default=10)
    parser.add_argument('-t', '--timeout', help='Jumlah maksimum waktu tunggu', default=10)

    args = parser.parse_args()

    scanner = DOVE(args.url, args.redirects, args.timeout)
    asyncio.run(scanner.jalankan(args.usr1, args.pwd1, args.usr2, args.pwd2))
