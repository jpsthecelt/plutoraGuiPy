import sys
import requests
import argparse
import pprint
import json
from Tkinter import *
from collections import OrderedDict

def update_database():
# write to DB...
    print("Updated DB")
    exit()

def quitIt():
    print("Done...bye!")
    exit()

def createReleaseJson(json_object, json_object2):
    print("(<createReleaseJson> - Not yet implemented)")
    pass

#
# This is a sample program to demonstrate programmatically grabbing JSON
# objects from a file and POSTing them into Plutora
#
def plutoraPush(clientid, clientsecret, plutora_username, plutora_password, object3push):

    # Set up JSON pretty-printing
    pp = pprint.PrettyPrinter(indent=4)

    # Setup for Plutora Get authorization-token (using the 
    # passed parameters, which were obtained from the file 
    # referenced on the command-line
    authTokenUrl = "https://usoauth.plutora.com/oauth/token"
    plutoraBaseUrl = 'https://usapi.plutora.com'
    payload = 'client_id=' + clientid + '&client_secret=' + clientsecret + '&' + 'grant_type=password&username='
    payload = payload + plutora_username + '&password=' + plutora_password + '&='
    
    headers = {
        'content-type': "application/x-www-form-urlencoded",
        'cache-control': "no-cache",
        'postman-token': "bc355474-15d1-1f56-6e35-371b930eac6f"
        }
    
    # Connect to get Plutora access token for subsequent queries
    authResponse = requests.post(authTokenUrl, data=payload, headers=headers)
    if authResponse.status_code != 200:
        print(authResponse.status_code)
        print('plutoraPush.py: Sorry! - [failed on getAuthToken]: ', authResponse.text)
        exit('Sorry, unrecoverable error; gotta go...')
    else:
        accessToken = authResponse.json()["access_token"]
    
    # Connect to get Plutora access token for subsequent queries
    authResponse = requests.post(authTokenUrl, data=payload, headers=headers)
    if authResponse.status_code != 200:
        print(authResponse.status_code)
        print('plutoraPush.py: Sorry! - [failed on getAuthToken]: ', authResponse.text)
        exit('Sorry, unrecoverable error; gotta go...')
    else:
        accessToken = authResponse.json()["access_token"]
    
        # Experiment -- Get Plutora information for all system releases, or systems, or just the organization-tree
        getReleases = '/releases'
        pushRelease = '/releases'
        getParticularRelease = '/releases/9d18a2dc-b694-4b20-971f-4944420f4038'
        getSystems = '/systems'
        getOrganizationsTree = '/organizations/tree'
        getHosts = '/hosts'
        getSystems = '/systems'
        getOrganizationsTree = '/organizations/tree'

        r = requests.get(plutoraBaseUrl+getReleases, data=payload, headers=headers)
        if r.status_code != 200:
            print('Get release status code: %i' % r.status_code)
            print('\nplutoraPush.py: too bad! - [failed on Plutora get]')
            exit('Sorry, unrecoverable error; gotta go...')
        else:
            releases = r.json
            pp.pprint(r.json())

    try:
        headers["content-type"] = "application/json"
        payload = """{ "additionalInformation": [], "name": "API created System 12", "vendor": "API created vendor", "status": "Active", "organizationId": "%s", "description": "Description of API created System 12" }""" % r.json()['childs'][0]['id']

        r = requests.post(plutoraBaseUrl+pushRelease, data=payload, headers=headers)
        if r.status_code != 201:
            print('Post new workitem status code: %i' % r.status_code)
            print('\nplutoraPush.py: too bad! - [failed on Plutora create POST]')
            print("header: ", headers)
            pp.pprint(r.json())
            exit('Sorry, unrecoverable error; gotta go...')
        else:
            pp.pprint(r.json())
    except:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

def consoleFillFields(fs_dict, db_fields):
    i = 0
    table_entries = []
    for k in fs_dict:
        v = fs_dict[k]
        l = v+': '
        orig = ""
        if db_fields[k] == None:
            e = '> ('+l+v+')'
            # Keep table of keys/labels/entry-fields/original-values/updated-values
            # (in this case, we're simply printing messages on the console and gathering
            # input)
        else:
            e = v
            orig = db_fields[k]

        n = raw_input(e)
        table_entries.append([k, l, e, orig, n])
        i += 1

    return table_entries

def menuFillFields(fs_dict, db_fields):
    root = Tk()
    uTf = Frame(root)
    uTf.pack()

    uTl = Label(uTf, text="Field Mapping")
    uTl.pack(side=LEFT)

    quitBtn = Button(uTf, text="Quit", command=quitIt)
    quitBtn.pack(side=RIGHT)

    submitBtn = Button(uTf, text="Submit Form", command=update_database)
    submitBtn.pack(side=RIGHT)

    uBf = Frame(root)
    uBf.pack(side=BOTTOM)

    i = 0
    table_entries = []
    for k in fs_dict:
        v = fs_dict[k]
        l = Label(uBf, text=v+': ')
        l.grid(row=i, column=0)
        e = Entry(uBf)
        e.grid(row=i, column=1)
        orig = ""
        if db_fields[k] == None:
            e.insert(len(v)+2, '('+v+')')
        else:
            e.insert(len(v), v)
            orig = db_fields[k]

        # Keep table of keys/labels/entry-fields/original-values/updated-values
        table_entries.append([k, l, e, orig, ""])
        i += 1

    root.mainloop()
    return 0

if __name__ == '__main__':
    # parse commandline and get appropriate passwords
    #    accepted format is python plutoraGuiPy.py -f <config fiiename>...
    #
    parser = argparse.ArgumentParser(description='Get user/password and configuration-information')
    parser.add_argument('-i', action='store', dest='config_filename', help='initial Config filename ')
    parser.add_argument('-p', action='store', dest='post_target_values',
                        help='filename containing JSON object prototype')
    parser.add_argument('-c', action='store', dest='release_id', help='release-id of release to copy')
    parser.add_argument('-f', action='store', dest='field_names_file', help='name of file containing field-names')
    parser.add_argument("--gui", default=True, action='store_true')

    results = parser.parse_args()

    if results.field_names_file == None:
        field_names_file = 'field_names.txt'

    with open(field_names_file) as fnames:
        fields = json.load(fnames, object_pairs_hook=OrderedDict)
    original_fields = fields
    config_filename = results.config_filename
    post_target_values = results.post_target_values

    if len(sys.argv[1:]) < 1:
        parser.usage
        parser.exit()

    if config_filename == None:
        config_filename = 'credentials.cfg'

    # If we don't specify a configfile on the commandline, assume one & try accessing
    # using the specified/assumed configfilename, grab ClientId & Secret from manual setup of Plutora Oauth authorization.
    try:
        with open(config_filename) as data_file:
            data = json.load(data_file)
        client_id = data["credentials"]["clientId"]
        client_secret = data["credentials"]["clientSecret"]
        plutora_username = data["credentials"]["plutoraUser"].replace('@', '%40')
        plutora_password = data["credentials"]["plutoraPassword"]

# in terms of getting POST prototype, can we grab it from: https://usapi.plutora.com/Help/Api/POST-releases
# body/div/2nd section/P/H2/H3/Pa/H3/P/A/TABLE/H3/Div/H2/H3/P/A/TABLE/H3/Div/Div/span/pre/#text
        with open(post_target_values) as json_data_file:
            data = json.load(json_data_file, object_pairs_hook=OrderedDict)
        json_object = data
        original_fields = data

        if results.gui == True:
            new_object = menuFillFields(fields, original_fields)
        else:
            new_object = consoleFillFields(fields, original_fields)

    except:
         # ex.msg is a string that looks like a dictionary
         print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
         exit('couldnt open file {0}'.format(post_target_values))
 
    createReleaseJson(new_object, original_fields)
    plutoraPush(client_id, client_secret, plutora_username, plutora_password, json_object)

