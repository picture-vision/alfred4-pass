import fnmatch
import os
import sys
import string

fuzzysearch = True
try:
    from fuzzywuzzy import fuzz
    from fuzzywuzzy import process
except:
    fuzzysearch = False

QUERY = sys.argv[1]

HOME = os.environ['HOME']
PASS_DIR = os.environ.get('PASSWORD_STORE_DIR',os.path.join(HOME, '.password-store/'))

def list_passwords():
    ret = []

    for root, dirnames, filenames in os.walk(PASS_DIR, True, None, True):
        for filename in fnmatch.filter(filenames, '*.gpg'):
            ret.append(os.path.join(root, filename.replace('.gpg','')).replace(PASS_DIR, ''))
    return sorted(ret, key=lambda s: s.lower())

def search_passwords(query):
    ''' Search passwords using the Fuzzy search method if fuzzywuzzy is available,
    or default to the filter-based search otherwise'''
    # disable fuzzy search for now
    # if fuzzysearch:
    #     return search_passwords_fuzzy(query)
    return search_passwords_filter(query)

def search_passwords_filter(query):
    ''' Search passwords using the filter-based search, which doesn't require fuzzywuzzy'''
    ret = []

    queryElems = query.split('.')

    passwords = list_passwords()
    for password in passwords:
        elemCnt = 0
        if password.lower().__contains__(query):
            ret.append(password)
    return ret

# fuzzy search is still in progress
def search_passwords_fuzzy(query):
    ''' Search passwords using the Fuzzy search method using fuzzywuzzy'''
    passwords = list_passwords()
    # return [entry[0] for entry in process.extract(query, passwords, limit=999)]
    return process.extractBests(query, passwords, limit=99, scorer=fuzz.token_sort_ratio)

def xmlize_items(items):
    items_a = []

    for item in items:
        list = item.rsplit("/", 1)
        name = list[-1]
        path = item if len(list) == 2 else ""
        
        items_a.append("""
    <item uid="%(item)s" arg="%(item)s" autocomplete="%(item)s">
        <title>%(name)s</title>
        <subtitle>%(path)s</subtitle>
    </item>
        """ % {'item': item, 'name': name, 'path': path, 'complete': item})

    return """
<?xml version="1.0"?>
<items>
    %s
</items>
    """ % '\n'.join(items_a)

items = search_passwords(QUERY)
print(xmlize_items(items))
