import re
import subprocess
import urllib

from prettytable import PrettyTable
import json
import requests


def process(ip, index, tables):
    requestForFullJson = requests.get(
        f"https://rest.db.ripe.net/search.json?query-string={ip}&flags=no-referenced&flags=no-irt&source=RIPE")
    requestForLessJson = requests.get(f"https://stat.ripe.net/data/address-space-hierarchy/data.json?resource={ip}")
    fulljson = json.loads(requestForFullJson.text)
    lessJso = json.loads(requestForLessJson.text)
    asn = re.findall("[A][S][\d]{4,6}", str(fulljson))
    country = lessJso["data"]['less_specific'][0]['country']
    if asn:
        try:
            provider = fulljson["objects"]['object'][1]['attributes']['attribute'][1]['value']
            tables.add_row([index, ip, str(asn[0]), provider, country])
        except IndexError:
            tables.add_row([index, ip, str(asn[0]), 'can not resolve', country])
    else:
        tables.add_row([index, ip, '*', '*', '*'])


def get_traceroute(hostname, table):
    try:
        urllib.request.urlopen('http://google.com')
    except:
        print("нет соединения")
        return False
    traceroute = subprocess.Popen(["tracert", '-w', '100', hostname], stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
    i = 0
    for line in iter(traceroute.stdout.readline, ""):

        a_line = line.decode('utf-8', errors='ignore').strip(' ')

        a = re.findall('[\d]{1,3}[.][\d]{1,3}[.][\d]{1,3}[.][\d]{1,3}', a_line)

        if line == b'\x92\xe0\xa0\xe1\xe1\xa8\xe0\xae\xa2\xaa\xa0 \xa7\xa0\xa2\xa5\xe0\xe8\xa5\xad\xa0.\r\n':
            break
        if a:
            i += 1
            process(a[0], i, table)
        else:
            continue
    return True


if __name__ == '__main__':
    table = PrettyTable()
    table.field_names = ["№", "IP", "AS", "Provider", "Country"]
    a = input()
    res = get_traceroute(a, table)
    if res:
        print(table)
