import requests
import argparse
import pprint
import json
from Tkinter import *
import tkMessageBox
import sys
import string
from collections import OrderedDict


#
# This is a sample program to demonstrate programmatically grabbing JSON
# objects from a file, verifying values, and POSTing them into Plutora
# (note that -f and -c are mutually-exclusive; the first one on the command-line
# takes precedence).
#
plutoraBaseUrl = 'https://usapi.plutora.com'


# return value from name-hash
def names(name):
    return name['value']

# Decide if the current argument is a guid or some other field
def isGuid(value):
    return all (c in set(string.hexdigits+'-') for c in value)

# Decide if the current argument is a guid or some other field
def isColor(value):
    if len(value) == 7 and value[0] == '#':
        return all (c in set(string.hexdigits+'#') for c in value)
    else:
        return False

# Given a 'sub-Url', do a get and determine if the element is a match to the supplied value.
# if not, emit error-message, else emit proper Guid
def getOrGetGuidFromValue(parmDesc, elem, value, header ):
    res = requests.get(plutoraBaseUrl+parmDesc, headers=header)

    if res.status_code != 200:
        return res.json()
    elif elem == 'raw_get':
        return res.text
    else:
        lookup_ids = res.json()

    lookup_id = [id_val for id_val in lookup_ids if id_val[elem] == value]

    if len(lookup_id) == 0:
        # (note use of names function, above)
        return 'must be one of %s' % (','.join(map(names,value)))
    else:
        return lookup_id[0]['id']

# verify that all mandatory release-fields have the appropriate values
# and return JSON-string with appropriately updated data, including
# substitutions of Guids for text values (in all Guid-fields).
def verifyReleaseGuidFields(updated_field_values, hdr ):

    # 'sanity-check' name/id/addn'l info & required fields
    if updated_field_values['additionalInformation'] == None or updated_field_values['additionalInformation'] == '[]':
        updated_field_values['additionalInformation'] = []

    value = updated_field_values['releaseTypeId']
    if value == None:
        return '{ReleaseTypeId is required}'
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/lookupfields/ReleaseType', 'value', value, hdr )
        if not isGuid(guid): return '{ReleaseTypeId is required}'
        else: updated_field_values['releaseTypeId'] = guid

    if updated_field_values['location'] == None:
        return '{Location is required}'

    value = updated_field_values['releaseStatusTypeId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/lookupfields/ReleaseStatusType', 'value', value, hdr)
        if not isGuid(guid): return  '{ReleaseStatusTypeId is required}'
        else: updated_field_values['releaseStatusTypeId'] = guid

    value = updated_field_values['releaseRiskLevelId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/lookupfields/ReleaseRiskLevel', 'value', value, hdr)
        if not isGuid(guid): return  '{ReleaseRiskLevelId is required}'
        else: updated_field_values['releaseRiskLevelId'] = guid

    value = updated_field_values['organizationId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/organizations', 'name', value, hdr)
        if not isGuid(guid): return '{organizationId is required}'
        else: updated_field_values['organizationId'] = guid

    value = updated_field_values['managerId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/users', 'userName', value, hdr)
        if not isGuid(guid): return  '{managerID is required}'
        else: updated_field_values['managerId'] = guid

    return json.dumps(updated_field_values)

def getAuth(creds):
    clientid = creds['client_id']
    clientsecret = creds['client_secret']
    plutora_username = creds['username']
    plutora_password = creds['password']

    # Set up JSON pretty-printing
    pp = pprint.PrettyPrinter(indent=4)

    # Setup for Plutora Get authorization-token (using the
    # passed parameters, which were obtained from the file
    # referenced on the command-line
    authTokenUrl = "https://usoauth.plutora.com/oauth/token"
    payload = 'client_id=' + clientid + '&client_secret=' + clientsecret + '&' + 'grant_type=password&username='
    payload = payload + plutora_username + '&password=' + plutora_password + '&='

    headers = { 'content-type': 'application/x-www-form-urlencoded', }

    # Connect to get Plutora access token for subsequent queries
    authResponse = requests.post(authTokenUrl, data=payload, headers=headers)
    if authResponse.status_code != 200:
        print(authResponse.status_code)
        print('updateDB: Sorry! - [failed on getAuthToken]: ', authResponse.text)
        exit('Sorry, unrecoverable error; gotta go...')
    else:
        accessToken = authResponse.json()["access_token"]

    authHeader = { 'Authorization': 'bearer %s' % (accessToken,) }
    authHeader["content-type"] = "application/json"
    return authHeader

def verifySystemGuidFields(updated_field_values, auth_header):
    # 'sanity-check' name/id/addn'l info & required fields
    if updated_field_values['additionalInformation'] == None or updated_field_values['additionalInformation'] == '[]':
        updated_field_values['additionalInformation'] = []

    value = updated_field_values['name']
    if value == None or isGuid(value):
        return '{Name is required}'

    value = updated_field_values['vendor']
    if value == None or isGuid(value):
        return '{Vendor is required}'

    available_status_types = {'Active', 'Inactive'}
    value = updated_field_values['status']
    if not value in available_status_types:
        return  '{SystemStatusTypeId is required and must be one of %s}' % (','.join(map(str,available_status_types)))

    value = updated_field_values['organizationId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/organizations', 'name', value, auth_header)
        if not isGuid(guid): return '{organizationId is required}'
        else: updated_field_values['organizationId'] = guid

    return json.dumps(updated_field_values)

def verifyEnvironmentGuidFields(updated_field_values, auth_header):
    # 'sanity-check' name/id info & required fields

    value = updated_field_values['name']
    if value == None or isGuid(value):
        return '{Name is required}'

    value = updated_field_values['vendor']
    if value == None or isGuid(value):
        return '{Vendor is required}'

    value = updated_field_values['linkedSystemId']
    if value == None or not isGuid(value):
        guid = getOrGetGuidFromValue('/systems', 'name', value, auth_header)
        if not isGuid(guid): return '{LinkedSystemId is required}'
        else: updated_field_values['linkedSystemId'] = guid

    value = updated_field_values['environmentStatusId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/lookupfields/EnvironmentStatus', 'name', value, auth_header)
        if not isGuid(guid): return '{EnvironmentStatus is required}'
        else: updated_field_values['EnvironmentStatus'] = guid
        return  '{EnvironmentStatus is required }'

    value = updated_field_values['usageWorkItemId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/lookupfields/UsedForWorkItem', 'value', value, auth_header)
        if not isGuid(guid): return '{UsedForWorkItem is required}'
        else: updated_field_values['usageWorkItemId'] = guid

    value = updated_field_values['isSharedEnvironment']
    available_status_types = {'True', 'False'}
    if not value in available_status_types:
        return  '{isSharedEnvironment is required and must be one of %s}' % (','.join(map(str,available_status_types)))
    else:
        value = eval(updated_field_values['isSharedEnvironment'])

    value = updated_field_values['color']
    if not isColor(value):
        return  '{Color is required and must be in the format #HHHHHH}'
    return json.dumps(updated_field_values)

def verifyChangesGuidFields(updated_field_values, auth_header):
    # 'sanity-check' name/id/addn'l info & required fields
    if updated_field_values['additionalInformation'] == None or updated_field_values['additionalInformation'] == '[]':
        updated_field_values['additionalInformation'] = []

    value = updated_field_values['name']
    if value == None or isGuid(value):
        return '{Name is required}'

    value = updated_field_values['vendor']
    if value == None or isGuid(value):
        return '{Vendor is required}'

    available_status_types = {'Active', 'Inactive'}
    value = updated_field_values['status']
    if not value in available_status_types:
        return  '{SystemStatusTypeId is required and must be one of %s}' % (','.join(map(str,available_status_types)))

    value = updated_field_values['organizationId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/organizations', 'name', value, auth_header)
        if not isGuid(guid): return '{organizationId is required}'
        else: updated_field_values['organizationId'] = guid

    return json.dumps(updated_field_values)

def updateSystemPlutoraDB(starting_fields, updated_json, auth_header):
    pp = pprint.PrettyPrinter(indent=4)

    try:
        # So, after generating payload, below, if return has the text 'required' in it, print out the error & quit
        payload = verifySystemGuidFields(updated_json, auth_header)
        if ''.join(map(str, payload)).find('required') != -1:
            pp.pprint(payload)
            exit('POST requires certain fields')

        r = requests.post(plutoraBaseUrl+'/systems', data=payload, headers=auth_header)
        if r.status_code != 201:
            print('Post new release status code: %i' % r.status_code)
            print('\nupdateReleasePlutoraDB.py: too bad! - [failed on Plutora create POST]')
            print("header: ", authHeader)
            pp.pprint(r.json())
            exit('Sorry, unrecoverable error; gotta go...')
        else:
            pp.pprint(r.json())
    except:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

# Given the original values (and any we supplied in the GUI, verify consistency
# & go update the DB
def updateReleasePlutoraDB(starting_fields, updated_json, auth_header):
    pp = pprint.PrettyPrinter(indent=4)

    try:
        payload = verifyReleaseGuidFields(updated_json, auth_header)
        if ''.join(map(str, updated_json)).find('required') != -1:
            pp.pprint(updated_json)
            exit('POST requires certain fields')

        r = requests.post(plutoraBaseUrl+'/releases', data=payload, headers=auth_header)
        if r.status_code != 201:
            print('Post new release status code: %i' % r.status_code)
            print('\nupdateReleasePlutoraDB.py: too bad! - [failed on Plutora create POST]')
            print("header: ", authHeader)
            pp.pprint(r.json())
            exit('Sorry, unrecoverable error; gotta go...')
        else:
            pp.pprint(r.json())
    except:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

def updateEnvironmentPlutoraDB(starting_fields, updated_json, auth_header):
    pp = pprint.PrettyPrinter(indent=4)

    try:
        payload = verifyEnvironmentGuidFields(updated_json, auth_header)
        if ''.join(map(str, updated_json)).find('required') != -1:
            pp.pprint(updated_json)
            exit('POST requires certain fields')

        r = requests.post(plutoraBaseUrl+'/environments', data=payload, headers=auth_header)
        if r.status_code != 201:
            print('Post new release status code: %i' % r.status_code)
            print('\nupdateReleasePlutoraDB.py: too bad! - [failed on Plutora create POST]')
            print("header: ", authHeader)
            pp.pprint(r.json())
            exit('Sorry, unrecoverable error; gotta go...')
        else:
            pp.pprint(r.json())
    except:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

def updateChangesPlutoraDB(starting_fields, updated_json, auth_header):
    pp = pprint.PrettyPrinter(indent=4)

    try:
        payload = verifyChangesGuidFields(updated_json, auth_header)
        if ''.join(map(str, updated_json)).find('required') != -1:
            pp.pprint(updated_json)
            exit('POST requires certain fields')

        r = requests.post(plutoraBaseUrl+'/releases', data=payload, headers=auth_header)
        if r.status_code != 201:
            print('Post new release status code: %i' % r.status_code)
            print('\nupdateReleasePlutoraDB.py: too bad! - [failed on Plutora create POST]')
            print("header: ", authHeader)
            pp.pprint(r.json())
            exit('Sorry, unrecoverable error; gotta go...')
        else:
            pp.pprint(r.json())
    except:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

# Vestigal; originally, could cause crash if --noguid is supplied on the command-line
# noop'd it out, below, for safety's sake
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

# given a list of dictionary elements, create a menu which allows updating.
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

#        verify_btn = Button(upper_frame, text="Verify Fields", command=root.quit)
#        verify_btn.pack(side=RIGHT)

        lower_frame = Frame(root)
        lower_frame.pack(side=BOTTOM)

        entries = OrderedDict()
        for field in self.fields:
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

# (might be used, later, to validate fields on-the-fly)
#        submit_btn = Button(upper_frame, text="Update Plutora", command=(lambda event, e=entries: self.fetch(e)))
#        submit_btn.pack(side=RIGHT)

        return entries

    def __init__(self, db_fields, auth_header):
        self.auth_header = auth_header
        self.root = root = Tk()
        self.entries = self.makeform(root, db_fields)
        root.mainloop()

def createRelease(post_tgt_values_file, authHeader):
    try:
        with open(post_tgt_values_file) as json_data_file:
            original_fields = json.load(json_data_file, object_pairs_hook=OrderedDict)
        if results.gui:
            updated_field_values = CreateMenu(original_fields, authHeader).fetch()
        else:
            #                updated_field_values = consoleFillFields(fields)
            print("Unimlemented:", "Non-gui functionality is currently unimplemented")

        updateReleasePlutoraDB(original_fields, updated_field_values, authHeader)

    except Exception,ex:
        # ex.msg is a string that looks like a dictionary
        print "EXCEPTION: %s " % ex.msg
        exit('Error during API processing [POST]')


def createSystem(post_tgt_values_filename, auth_header):
    # Set up JSON prettyPrinting
    pp = pprint.PrettyPrinter(indent=4)

    # Setup to query Maersk Plutora instances
    plutoraBaseUrl= 'https://usapi.plutora.com'
    postSystem = '/systems'

    # OK; try creating a new system...
    try:
        with open(post_tgt_values_file) as json_data_file:
            original_fields = json.load(json_data_file, object_pairs_hook=OrderedDict)
        if results.gui:
            updated_field_values = CreateMenu(original_fields, authHeader).fetch()
        else:
            #                updated_field_values = consoleFillFields(fields)
            print("Unimlemented:", "Non-gui functionality is currently unimplemented")

        updateSystemPlutoraDB(original_fields, updated_field_values, authHeader)

    except Exception,ex:
        # ex.msg is a string that looks like a dictionary
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

def createEnvironment(post_tgt_values_filename, auth_header):
    # Set up JSON prettyPrinting
    pp = pprint.PrettyPrinter(indent=4)

    # Setup to query Maersk Plutora instances
    plutoraBaseUrl= 'https://usapi.plutora.com'
    postEnviron = '/environments'

    # OK; try creating a new system...
    try:
        with open(post_tgt_values_file) as json_data_file:
            original_fields = json.load(json_data_file, object_pairs_hook=OrderedDict)
        if results.gui:
            updated_field_values = CreateMenu(original_fields, authHeader).fetch()
        else:
            #                updated_field_values = consoleFillFields(fields)
            print("Unimlemented:", "Non-gui functionality is currently unimplemented")

        updateEnvironmentPlutoraDB(original_fields, updated_field_values, authHeader)

    except Exception,ex:
        # ex.msg is a string that looks like a dictionary
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

def createChanges(post_tgt_values_filename, auth_header):
    # Set up JSON prettyPrinting
    pp = pprint.PrettyPrinter(indent=4)

    # Setup to query Maersk Plutora instances
    plutoraBaseUrl= 'https://usapi.plutora.com'
    postSystem = '/systems'

    # OK; try creating a new system...
    try:
        with open(post_tgt_values_file) as json_data_file:
            original_fields = json.load(json_data_file, object_pairs_hook=OrderedDict)
        if results.gui:
            updated_field_values = CreateMenu(original_fields, authHeader).fetch()
        else:
            #                updated_field_values = consoleFillFields(fields)
            print("Unimlemented:", "Non-gui functionality is currently unimplemented")

        updateChangesPlutoraDB(original_fields, updated_field_values, authHeader)

    except Exception,ex:
        # ex.msg is a string that looks like a dictionary
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

def deleteEntity(item2del, aHeader):
    if '/environments/' in item2del:
#        res = requests.delete(plutoraBaseUrl+item2del, headers=aHeader)
        res = requests.request('DELETE',  plutoraBaseUrl+item2del, headers=aHeader)
    elif '/releases/' in item2del:
        res = requests.delete(plutoraBaseUrl+item2del, headers=aHeader)
    elif '/systems/' in item2del:
        res = requests.delete(plutoraBaseUrl+item2del, headers=aHeader)
    elif '/changes/' in item2del:
        res = requests.delete(plutoraBaseUrl+item2del, headers=aHeader)
    else:
        return '{ Delete: Bad ResourceName }'

    if res.status_code != 200:
        return res.json()
    else:
        return '{ failed to delete %s}' % res.text


if __name__ == '__main__':
    # parse commandline and get appropriate passwords
    #    accepted format is python plutoraGuiPy.py -f <config fiiename>...
    #
    parser = argparse.ArgumentParser(description='Get user/password and configuration-information')
    parser.add_argument('-i', action='store', dest='config_filename', help='initial Config filename ')
    parser.add_argument('-x', action='store', dest='delete_entity', help='entity to delete')
    parser.add_argument('-p', action='store', dest='post_tgt_values_file',
                        help='filename containing JSON object prototype')
    parser.add_argument('-c', action='store', dest='release_id_to_copy', help='release-id of release to copy')
    parser.add_argument("--gui", default=True, action='store_true')
    results = parser.parse_args()

    if len(sys.argv[1:]) < 1:
        parser.usage
        parser.exit()

# (potentially used for later)
# I'd like to be able to 'grab' prototype from the website, a la wget,
# do an xmltodict, select xml2json(doc["html"]["body"]["div"]["section"][1]["div"]["div"])
# and then a xml2python to get field-names/types

    if results.release_id_to_copy != None:
        release_id_to_copy = results.release_id_to_copy

    config_filename = results.config_filename
    if results.config_filename == None:
        config_filename = 'credentials.cfg'

    # If we don't specify a configfile on the commandline, assume one & try accessing
    # using the specified/assumed configfilename, grab ClientId & Secret from manual setup of Plutora Oauth authorization.
    try:
        with open(config_filename) as data_file:
            data = json.load(data_file)
        credentials = {
            'client_id': data["credentials"]["client_id"],
            'client_secret': data["credentials"]["client_secret"],
            'username': data["credentials"]["username"].replace('@', '%40'),
            'password': data["credentials"]["password"]
        }

        post_tgt_values_file = results.post_tgt_values_file
        authHeader = getAuth(credentials)

        # commandline must be of the form /environments/<guid>...
        delEntity = results.delete_entity
        if delEntity != None:
            deleteEntity(delEntity, authHeader)
            exit('gone...')

        # Given a filename-on-the-commandline, cycle through the different types of files (suffixes)
        # calling the appropriate createX routine.
        available_suffix_types = ['.rls', '.sys', '.env', '.chg']
        if post_tgt_values_file != None and len(filter(lambda k: k in post_tgt_values_file, available_suffix_types)) > 0:
            if post_tgt_values_file.find('.sys') != -1:
                createSystem(post_tgt_values_file, authHeader)

            if post_tgt_values_file.find('.rls') != -1:
                createRelease(post_tgt_values_file, authHeader)

            if post_tgt_values_file.find('.env') != -1:
                createEnvironment(post_tgt_values_file, authHeader)

            if post_tgt_values_file.find('.rls') != -1:
                createChanges(post_tgt_values_file, authHeader)
        else:
# in terms of getting POST prototype, can we grab it from: https://usapi.plutora.com/Help/Api/POST-releases
# body/div/2nd section/P/H2/H3/Pa/H3/P/A/TABLE/H3/Div/H2/H3/P/A/TABLE/H3/Div/Div/span/pre/#text
# OR, if doc is set to x.text, maybe something like:
# d = json.loads(doc["html"]["body"]["div"]["section"][1]["div"]["div"][1]['div'][0]['pre']['#text'],object_pairs_hook=OrderedDict)

            # We're currently simply using the fields 'garnered' from the JSON parameter file-read.
# ****** TODO: Have to figure a way to do systems, environments, releases, and changes, here
            if (not post_tgt_values_file and results.release_id_to_copy != None):
                #  original_fields = json.load(getOrGetGuidFromValue('/releases/'+results.release_id_to_copy, 'raw_get', 0, authHeader ), object_pairs_hook=OrderedDict)
                release_copy = getOrGetGuidFromValue('/releases/'+results.release_id_to_copy, 'raw_get', 0, authHeader )
                original_fields = json.loads(release_copy, object_pairs_hook=OrderedDict)
                updated_field_values = CreateMenu(original_fields, authHeader).fetch()
                updateReleasePlutoraDB(original_fields, updated_field_values, authHeader)

    except Exception as e:
         # ex.msg is a string that looks like a dictionary
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0], sys.exc_info()[1].message)
#         exit('couldnt open file {0}'.format(post_tgt_values_file))



