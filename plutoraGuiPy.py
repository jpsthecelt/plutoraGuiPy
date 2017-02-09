import requests
import argparse
import pprint
import json
from Tkinter import *
import sys
import string
from collections import OrderedDict


#
# This is a sample program to demonstrate programmatically grabbing JSON
# objects from a file, verifying values, and POSTing them into Plutora
# (note that -f and -c are mutually-exclusive; the first one on the command-line
# takes precedence). Additionally, once there's a -x on the command-line, all
# further arguments are ignored.
#
plutoraBaseUrl = 'https://usapi.plutora.com'
BinaryTrueFalse = {'True', 'False'}

# Decide if the current argument is a guid or some other field
def isGuid(value):
    value = value.encode('ascii', 'ignore')
    if not value:
        return False
    else:
        all (c in set(string.hexdigits+'-') for c in value)

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
        # (note use of names function, above) [decided to make this a lambda-function, instead]
        return 'must be one of %s' % (','.join(map(lambda k: k['value'], value)))
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
        print('getAuth: Sorry! - [failed on getAuthToken]: ', authResponse.text)
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
    available_status_types = BinaryTrueFalse
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

def updateSystemPlutoraDB(starting_fields, updated_json_dict, is_copy, auth_header):
    pp = pprint.PrettyPrinter(indent=4)

    try:
        # So, after generating payload, below, if return has the text 'required' in it, print out the error & quit
        if is_copy:
            payload = json.dumps(updated_json_dict)
        else:
            payload = verifySystemGuidFields(updated_json_dict, auth_header)
            if ''.join(map(str, payload)).find('required') != -1:
                pp.pprint(payload)
                exit('POST requires certain fields')

        r = requests.post(plutoraBaseUrl+'/systems', data=payload, headers=auth_header)
        if r.status_code != 201:
            print('Post new release status code: %i' % r.status_code)
            print('\nupdateSystemPlutoraDB.py: too bad! - [failed on Plutora create POST]')
            print("header: ", auth_header)
            pp.pprint(r.json())
            exit('Sorry, unrecoverable error; gotta go...')
        else:
            return '{Created System: %s(%s)}' % (r.json()['name'], r.json()['id'])

    except:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

# Given the original values (and any we supplied in the GUI, verify consistency
# & go update the DB
def updateReleasePlutoraDB(starting_fields, updated_json_dict, is_copy, auth_header):
    pp = pprint.PrettyPrinter(indent=4)

    try:
        if is_copy:
            updated_json_dict['additionalInformation'] = []
            mgrId = updated_json_dict['managerId']
            if not isGuid(mgrId):
                guid = getOrGetGuidFromValue('/users', 'userName', mgrId, auth_header)
                # TODO: Originally used if not isGuid(guid), and it kept coming back as 'None', when
                #       it wasn't really, so I directly code for the error-message
                if 'must be one' in guid:
                    return '{ManagerId is required}'
                else:
                    updated_json_dict['managerId'] = guid

            payload = json.dumps(updated_json_dict)
        else:
            payload = verifyReleaseGuidFields(updated_json_dict, auth_header)
            if ''.join(map(str, updated_json_dict)).find('required') != -1:
                pp.pprint(updated_json_dict)
                exit('POST requires certain fields')

        r = requests.post(plutoraBaseUrl+'/releases', data=payload, headers=auth_header)
        if r.status_code != 201:
            print('Post new release status code: %i' % r.status_code)
            print('\nupdateReleasePlutoraDB.py: too bad! - [failed on Plutora create POST]')
            print("header: ", auth_header)
            pp.pprint(r.json())
            exit('Sorry, unrecoverable error; gotta go...')
        else:
            return '{Created Release: %s(%s)}' % (r.json()['name'],r.json()['id'])

    except:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

def updateEnvironmentPlutoraDB(starting_fields, updated_json_dict, is_copy, auth_header):
    pp = pprint.PrettyPrinter(indent=4)

    try:
        if is_copy:
            if not updated_json_dict['isSharedEnvironment'] in BinaryTrueFalse:
                updated_json_dict['isSharedEnvironment'] = 'False'
            if not updated_json_dict['isSharedEnvironment'] == "[]":
                updated_json_dict['hosts'] = []
            payload = json.dumps(updated_json_dict)
        else:
            payload = verifyEnvironmentGuidFields(updated_json_dict, auth_header)
            if ''.join(map(str, updated_json_dict)).find('required') != -1:
                pp.pprint(updated_json_dict)
                exit('POST requires certain fields')

        r = requests.post(plutoraBaseUrl+'/environments', data=payload, headers=auth_header)
        if r.status_code != 201:
            print('Post new release status code: %i' % r.status_code)
            print('\nupdateEnvironmentPlutoraDB.py: too bad! - [failed on Plutora create POST]')
            print("header: ", auth_header)
            pp.pprint(r.json())
            exit('Sorry, unrecoverable error; gotta go...')
        else:
            return '{Created Environment: %s(%s)}' % (r.json()['name'], r.json()['id'])

    except:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

def updateChangesPlutoraDB(starting_fields, updated_json_dict, is_copy, auth_header):
    pp = pprint.PrettyPrinter(indent=4)

    try:
        if is_copy:
            payload = json.dumps(updated_json_dict)
        else:
            payload = verifyChangesGuidFields(updated_json_dict, auth_header)
            if ''.join(map(str, updated_json_dict)).find('required') != -1:
                pp.pprint(updated_json_dict)
                exit('POST requires certain fields')

        r = requests.post(plutoraBaseUrl+'/changes', data=payload, headers=auth_header)
        if r.status_code != 201:
            print('Post new release status code: %i' % r.status_code)
            print('\nupdateChangesPlutoraDB.py: too bad! - [failed on Plutora create POST]')
            print("header: ", auth_header)
            pp.pprint(r.json())
            exit('Sorry, unrecoverable error; gotta go...')
        else:
            return '{Created Change: %s(%s)}' % (r.json()['name'], r.json()['id'])
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

def createRelease(use_gui, post_tgt_values_file, auth_header):
    try:
        with open(post_tgt_values_file) as json_data_file:
            org_fields = updated_fields = json.load(json_data_file, object_pairs_hook=OrderedDict)
        if use_gui:
            updated_fields = CreateMenu(org_fields, auth_header).fetch()

        updateReleasePlutoraDB(org_fields, updated_fields, auth_header)

    except Exception as e:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0], sys.exc_info()[1].message)
        print "Exception: ", e
        exit('Error during API processing [POST]')


def createSystem(use_gui, post_tgt_values_filename, auth_header):
    # Set up JSON prettyPrinting
    pp = pprint.PrettyPrinter(indent=4)

    # Setup to query Maersk Plutora instances
    plutoraBaseUrl= 'https://usapi.plutora.com'
    postSystem = '/systems'

    # OK; try creating a new system...
    try:
        with open(post_tgt_values_filename) as json_data_file:
            org_fields = updated_fields = json.load(json_data_file, object_pairs_hook=OrderedDict)
        if use_gui:
            updated_fields = CreateMenu(org_fields, auth_header).fetch()

        updateSystemPlutoraDB(org_fields, updated_fields, auth_header)

    except Exception as e:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0], sys.exc_info()[1].message)
        print "Exception: ", e
        exit('Error during API processing [POST]')

def createEnvironment(use_gui, post_tgt_values_filename, auth_header):
    # Set up JSON prettyPrinting
    pp = pprint.PrettyPrinter(indent=4)

    # Setup to query Plutora instances
    plutoraBaseUrl= 'https://usapi.plutora.com'
    postEnviron = '/environments'

    # OK; try creating a new system...
    try:
        with open(post_tgt_values_filename) as json_data_file:
            org_fields = updated_fields = json.load(json_data_file, object_pairs_hook=OrderedDict)
        if use_gui:
            updated_fields = CreateMenu(org_fields, auth_header).fetch()

        updateEnvironmentPlutoraDB(org_fields, updated_fields, auth_header)

    except Exception as e:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        print "Exception: ", e
        exit('Error during API processing [POST]')

def createChanges(use_gui, post_tgt_values_filename, auth_header):
    # Set up JSON prettyPrinting
    pp = pprint.PrettyPrinter(indent=4)

    # Setup to query Maersk Plutora instances
    plutoraBaseUrl= 'https://usapi.plutora.com'
    postSystem = '/systems'

    # OK; try creating a new system...
    try:
        with open(post_tgt_values_filename) as json_data_file:
            org_fields = updated_fields = json.load(json_data_file, object_pairs_hook=OrderedDict)
        if use_gui:
            updated_fields = CreateMenu(org_fields, authHeader).fetch()

        updateChangesPlutoraDB(org_fields, updated_fields, auth_header)

    except Exception as e:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        print "Exception: ", e
        exit('Error during API processing [POST]')

def deleteEntity(item2del, auth_header):
    if '/environments/' in item2del:
        res = requests.delete(plutoraBaseUrl+item2del, headers=auth_header)
    elif '/releases/' in item2del:
        res = requests.delete(plutoraBaseUrl+item2del, headers=auth_header)
    elif '/systems/' in item2del:
        res = requests.delete(plutoraBaseUrl+item2del, headers=auth_header)
    elif '/changes/' in item2del:
        res = requests.delete(plutoraBaseUrl+item2del, headers=auth_header)
    else:
        return '{ Delete: Bad ResourceName }'

    if res.status_code != 200:
        return res.json()
    else:
        return '{ deleted %s}' % item2del


if __name__ == '__main__':
    # parse commandline and get appropriate passwords
    #    accepted format is python plutoraGuiPy.py -i <config fiiename>...
    #
    parser = argparse.ArgumentParser(description='Get user/password and configuration-information')
    parser.add_argument('-i', action='store', dest='config_filename', help='initial Config filename ')
    parser.add_argument('-x', action='store', dest='delete_entity', help='entity to delete')
    parser.add_argument('-p', action='store', dest='post_tgt_values_file',
                        help='filename containing JSON object prototype')
    parser.add_argument('-c', action='store', dest='guid_id_to_copy', help='release-id of release to copy')
    parser.add_argument("--gui", default=False, action='store_true')
    parser.add_argument("--datepick", default=False, action='store_true')
    results = parser.parse_args()

    if len(sys.argv[1:]) < 1:
        parser.usage
        parser.exit()

# (potentially used for later)
# I'd like to be able to 'grab' prototype from the website, a la wget,
# do an xmltodict, select xml2json(doc["html"]["body"]["div"]["section"][1]["div"]["div"])
# and then a xml2python to get field-names/types

    config_filename = results.config_filename
    if results.config_filename == None:
        config_filename = 'credentials.cfg'

    if results.gui and results.datepick:
        print('Datepicker Not Implemented, yet')

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

        # Handle the case where we must delete an entity. Note that the
        # commandline must be similar to the form '-x /environments/<guid>'...
        delEntity = results.delete_entity
        if delEntity:
            print(deleteEntity(delEntity, authHeader))
            exit('done, for now...')

        # Given a filename or guid-on-the-commandline, cycle through the different types of files (suffixes)
        # calling the appropriate createX routine.
        available_suffix_types = ['.rls', '.sys', '.env', '.chg']
        if post_tgt_values_file and len(filter(lambda k: k in post_tgt_values_file, available_suffix_types)) > 0:
            if post_tgt_values_file.find('.sys') != -1:
                createSystem(results.gui, post_tgt_values_file, authHeader)
            elif post_tgt_values_file.find('.rls') != -1:
                createRelease(results.gui, post_tgt_values_file, authHeader)
            elif post_tgt_values_file.find('.env') != -1:
                createEnvironment(results.gui, post_tgt_values_file, authHeader)
            elif post_tgt_values_file.find('.rls') != -1:
                createChanges(results.gui, post_tgt_values_file, authHeader)
            else:
                print '{expected one of %s file suffixes}' % (','.join(map(str,available_suffix_types)))
        else:
# Although it would be possible to get a POST prototype from https://usapi.plutora.com/Help/Api/POST-releases
# body/div/2nd section/P/H2/H3/Pa/H3/P/A/TABLE/H3/Div/H2/H3/P/A/TABLE/H3/Div/Div/span/pre/#text
# for example, we're just assuming that the initial values from the post_X_values.YYY file includes all the
# necessary fields with the expected values, otherwise the update will fail.

# if we were trying to grab a prototype from the help web-page and if doc was set to x.text, maybe we could do
# something like: d = json.loads(doc["html"]["body"]["div"]["section"][1]["div"]["div"][1]['div'][0]['pre']['#text'],object_pairs_hook=OrderedDict)

            item2copy = results.guid_id_to_copy
            # As mentioned above, notice We're currently simply using the fields 'garnered' from the JSON parameter file-read.
            if (not post_tgt_values_file and item2copy):
                isCopy = True
                entity_copy = getOrGetGuidFromValue(item2copy, 'raw_get', 0, authHeader )
                original_fields = updated_field_values = json.loads(entity_copy, object_pairs_hook=OrderedDict)
                if results.gui:
                    updated_field_values = CreateMenu(original_fields, authHeader).fetch()

                if '/environments/' in item2copy:
                    print(updateEnvironmentPlutoraDB(original_fields, updated_field_values, isCopy, authHeader))
                elif '/releases/' in item2copy:
                    print(updateReleasePlutoraDB(original_fields, updated_field_values, isCopy, authHeader))
                elif '/systems/' in item2copy:
                    print(updateSystemPlutoraDB(original_fields, updated_field_values, isCopy, authHeader))
                elif '/changes/' in item2copy:
                    print(updateChangesPlutoraDB(original_fields, updated_field_values, isCopy, authHeader))
                else:
                    print '{ copy: Bad GuidName }'

    except Exception as e:
         # ex.msg is a string that looks like a dictionary
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0], sys.exc_info()[1].message)
        print "Exception: ", e

