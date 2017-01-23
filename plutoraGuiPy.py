import sys

import requests
import argparse
import pprint
import json
from Tkinter import *
import ttk
from collections import OrderedDict

#
# This is a sample program to demonstrate programmatically grabbing JSON
# objects from a file and POSTing them into Plutora
#
def updatePlutoraDB(creds, updated_json):
    clientid = creds['clientid']
    clientsecret = creds['clientsecret']
    plutora_username = creds['plutora_username']
    plutora_password = creds['plutora_passwords']

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
        print('updatePlutoraDB.py: Sorry! - [failed on getAuthToken]: ', authResponse.text)
        exit('Sorry, unrecoverable error; gotta go...')
    else:
        accessToken = authResponse.json()["access_token"]
    
    # Connect to get Plutora access token for subsequent queries
    authResponse = requests.post(authTokenUrl, data=payload, headers=headers)
    if authResponse.status_code != 200:
        print(authResponse.status_code)
        print('updatePlutoraDB.py: Sorry! - [failed on getAuthToken]: ', authResponse.text)
        exit('Sorry, unrecoverable error; gotta go...')
    else:
        accessToken = authResponse.json()["access_token"]
    
        # Experiment -- Get Plutora information for all system releases, or systems, or just the organization-tree
        getReleases = pushRelease = '/releases'

#        getParticularRelease = '/releases/9d18a2dc-b694-4b20-971f-4944420f4038'
#        getSystems = '/systems'
#        getOrganizationsTree = '/organizations/tree'
#        getHosts = '/hosts'
#        getSystems = '/systems'
#        getOrganizationsTree = '/organizations/tree'

#        # Get specified Plutora Release info
#        r = requests.get(plutoraBaseUrl+getReleases, data=payload, headers=headers)
#        if r.status_code != 200:
#            print('Get release status code: %i' % r.status_code)
#            print('\nupdatePlutoraDB.py: too bad! - [failed on Plutora get]')
#            exit('Sorry, unrecoverable error; gotta go...')
#        else:
#            releases = r.json
#            pp.pprint(r.json())

    try:
        headers["content-type"] = "application/json"
        payload = json.dumps(updated_json)
#        payload = """{ "additionalInformation": [], "name": "API created System 12", "vendor": "API created vendor", "status": "Active", "organizationId": "%s", "description": "Description of API created System 12" }""" % r.json()['childs'][0]['id']

        r = requests.post(plutoraBaseUrl+pushRelease, data=payload, headers=headers)
        if r.status_code != 201:
            print('Post new workitem status code: %i' % r.status_code)
            print('\nupdatePlutoraDB.py: too bad! - [failed on Plutora create POST]')
            print("header: ", headers)
            pp.pprint(r.json())
            exit('Sorry, unrecoverable error; gotta go...')
        else:
            pp.pprint(r.json())
    except:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

def consoleFillFields(db_fields):
    i = 0
    table_entries = []
    for k in db_fields:
        v = db_fields[k]
        l = k+': '
        orig = ""
        if v == None:
            e = '> ('+l+k+')'
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

class CreateMenu:
    def fetch(self):
        new_values = OrderedDict()
        for entry in self.entries:
            new_values[entry] = self.entries[entry].get()
        return new_values

    def makeform(self, root, db_fields):
        root.title("Send Updated Form to Plutora")
        self.fields = db_fields

        upper_frame = Frame(root)
        upper_frame.pack(side=TOP)

        upper_top_label = Label(upper_frame, text="Update Plutora DB Record")
        upper_top_label.pack(side=TOP)

        quit_btn = Button(upper_frame, text="Done", command=root.quit)
        quit_btn.pack(side=RIGHT)

        lower_frame = Frame(root)
        lower_frame.pack(side=BOTTOM)

        entries = OrderedDict()
        for field in fields:
            row = Frame(lower_frame)
            lbl = Label(row, text=field+': ', anchor='w')
            ent = Entry(row)
            if db_fields[field] == None:
                ent.insert(0, "")
            else:
                ent.insert(END,db_fields[field])
            row.pack(side=TOP, fill=X, padx=5, pady=5)
            lbl.pack(side=LEFT)
            ent.pack(side=RIGHT, expand=YES, fill=X)
            entries[field] = ent

#        submit_btn = Button(upper_frame, text="Update Plutora", command=(lambda event, e=entries: self.fetch(e)))
#        submit_btn.pack(side=RIGHT)

        return entries

    def __init__(self, db_fields):
        self.root = root = Tk()
        self.entries = self.makeform(root, db_fields)
        root.mainloop()


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

    if len(sys.argv[1:]) < 1:
        parser.usage
        parser.exit()

# Lifielde to be able to 'grab it' from the website, a la wget from
# do an xmltodict, select xml2json(doc["html"]["body"]["div"]["section"][1]["div"]["div"])
# and then a xml2python to get field-names/types
    field_names_file = results.field_names_file
    if results.field_names_file == None:
        field_names_file = 'field_names.txt'

    config_filename = results.config_filename
    if results.config_filename == None:
        config_filename = 'credentials.cfg'

    # If we don't specify a configfile on the commandline, assume one & try accessing
    # using the specified/assumed configfilename, grab ClientId & Secret from manual setup of Plutora Oauth authorization.
    try:
        with open(config_filename) as data_file:
            data = json.load(data_file)
        credentials = {
            'client_id': data["credentials"]["clientId"],
            'client_secret': data["credentials"]["clientSecret"],
            'plutora_username': data["credentials"]["plutoraUser"].replace('@', '%40'),
            'plutora_password': data["credentials"]["plutoraPassword"]
        }

        # Open field-names file
        with open(field_names_file) as fnames:
            fields = json.load(fnames, object_pairs_hook=OrderedDict)
        original_fields = fields
        post_target_values = results.post_target_values

# in terms of getting POST prototype, can we grab it from: https://usapi.plutora.com/Help/Api/POST-releases
# body/div/2nd section/P/H2/H3/Pa/H3/P/A/TABLE/H3/Div/H2/H3/P/A/TABLE/H3/Div/Div/span/pre/#text
# OR, if doc is set to x.text, maybe something like:
# d = json.loads(doc["html"]["body"]["div"]["section"][1]["div"]["div"][1]['div'][0]['pre']['#text'],object_pairs_hook=OrderedDict)

# Of course, an alternative would be to simply use the fields 'garnered' from the previous read.
        with open(post_target_values) as json_data_file:
            fields = json.load(json_data_file, object_pairs_hook=OrderedDict)

        if results.gui:
            updated_field_values = CreateMenu(fields).fetch()
        else:
            new_field_values = consoleFillFields(fields)

    except:
         # ex.msg is a string that looks like a dictionary
         print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0], sys.exc_info()[1].message)
         exit('couldnt open file {0}'.format(post_target_values))


#    updated_field_values = menu_obj.fetch()
    updatePlutoraDB(credentials, updated_field_values)

