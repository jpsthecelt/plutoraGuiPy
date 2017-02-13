import requests
import argparse
import pprint
import json
from Tkinter import *
import sys
import string
import calendar
import datetime
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
        return all (c in set(string.hexdigits+'-') for c in value)

# Decide if the current argument is a guid or some other field
def isColor(value):
    if len(value) == 7 and value[0] == '#':
        return all (c in set(string.hexdigits+'#') for c in value)
    else:
        return False

def cleanseNullListAsString(field):
    if type(field) == str and (field == '[]' or field == None):
        return []
    else:
        return field

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

class DatePicker:
    def __init__(self, parent, values):
        self.values = values
        self.parent = parent
        self.cal = calendar.TextDatePicker(calendar.SUNDAY)
        self.year = datetime.date.today().year
        self.month = datetime.date.today().month
        self.wid = []
        self.day_selected = 1
        self.month_selected = self.month
        self.year_selected = self.year
        self.day_name = ''

        self.setup(self.year, self.month)

    def clear(self):
        for w in self.wid[:]:
            w.grid_forget()
            #w.destroy()
            self.wid.remove(w)

    def go_prev(self):
        if self.month > 1:
            self.month -= 1
        else:
            self.month = 12
            self.year -= 1
        #self.selected = (self.month, self.year)
        self.clear()
        self.setup(self.year, self.month)

    def go_next(self):
        if self.month < 12:
            self.month += 1
        else:
            self.month = 1
            self.year += 1

        #self.selected = (self.month, self.year)
        self.clear()
        self.setup(self.year, self.month)

    def selection(self, day, name):
        self.day_selected = day
        self.month_selected = self.month
        self.year_selected = self.year
        self.day_name = name

        #data
        self.values['day_selected'] = day
        self.values['month_selected'] = self.month
        self.values['year_selected'] = self.year
        self.values['day_name'] = name
        self.values['month_name'] = calendar.month_name[self.month_selected]

        self.clear()
        self.setup(self.year, self.month)

    def setup(self, y, m):
        left = Button(self.parent, text='<', command=self.go_prev)
        self.wid.append(left)
        left.grid(row=0, column=1)

        header = Label(self.parent, height=2, text='{}   {}'.format(calendar.month_abbr[m], str(y)))
        self.wid.append(header)
        header.grid(row=0, column=2, columnspan=3)

        right = Button(self.parent, text='>', command=self.go_next)
        self.wid.append(right)
        right.grid(row=0, column=5)

        days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        for num, name in enumerate(days):
            t = Label(self.parent, text=name[:3])
            self.wid.append(t)
            t.grid(row=1, column=num)

        for w, week in enumerate(self.cal.monthdayscalendar(y, m), 2):
            for d, day in enumerate(week):
                if day:
                    #print(calendar.day_name[day])
                    b = Button(self.parent, width=1, text=day, command=lambda day=day:self.selection(day, calendar.day_name[(day-1) % 7]))
                    self.wid.append(b)
                    b.grid(row=w, column=d)

        sel = Label(self.parent, height=2, text='{} {} {} {}'.format(
            self.day_name, calendar.month_name[self.month_selected], self.day_selected, self.year_selected))
        self.wid.append(sel)
        sel.grid(row=8, column=0, columnspan=7)

        ok = Button(self.parent, width=5, text='OK', command=self.kill)
        self.wid.append(ok)
        ok.grid(row=9, column=2, columnspan=3, pady=10)

        def kill(self):
            self.parent.destroy()

# verify that all mandatory release-fields have the appropriate values
# and return JSON-string with appropriately updated data, including
# substitutions of Guids for text values (in all Guid-fields).
def verifyReleaseGuidFields(updated_fields_dict, hdr ):

    # 'sanity-check' name/id/addn'l info & required fields
    updated_fields_dict['additionalInformation'] = cleanseNullListAsString(updated_fields_dict['additionalInformation'])
    if 'OrderedDict' in updated_fields_dict['additionalInformation']:
        updated_fields_dict['additionalInformation'] = []

    value = updated_fields_dict['releaseTypeId']
    if value == None:
        return '{ReleaseTypeId is required}'
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/lookupfields/ReleaseType', 'value', value, hdr )
        if not isGuid(guid): return '{ReleaseTypeId is required}'
        else: updated_fields_dict['releaseTypeId'] = guid

    if updated_fields_dict['location'] == None:
        return '{Location is required}'

    value = updated_fields_dict['releaseStatusTypeId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/lookupfields/ReleaseStatusType', 'value', value, hdr)
        if not isGuid(guid): return  '{ReleaseStatusTypeId is required}'
        else: updated_fields_dict['releaseStatusTypeId'] = guid

    value = updated_fields_dict['releaseRiskLevelId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/lookupfields/ReleaseRiskLevel', 'value', value, hdr)
        if not isGuid(guid): return  '{ReleaseRiskLevelId is required}'
        else: updated_fields_dict['releaseRiskLevelId'] = guid

    value = updated_fields_dict['organizationId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/organizations', 'name', value, hdr)
        if not isGuid(guid): return '{organizationId is required}'
        else: updated_fields_dict['organizationId'] = guid

    value = updated_fields_dict['managerId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/users', 'userName', value, hdr)
        if not isGuid(guid): return  '{managerID is required}'
        else: updated_fields_dict['managerId'] = guid

    return json.dumps(updated_fields_dict)

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

def verifySystemGuidFields(updated_field_dict, auth_header):
    # 'sanity-check' name/id/addn'l info & required fields
    updated_field_dict['additionalInformation'] = cleanseNullListAsString(updated_field_dict['additionalInformation'])
    if 'OrderedDict' in updated_field_dict['additionalInformation']:
        updated_field_dict['additionalInformation'] = []

    value = updated_field_dict['name']
    if value == None or isGuid(value):
        return '{Name is required}'

    value = updated_field_dict['vendor']
    if value == None or isGuid(value):
        return '{Vendor is required}'

    available_status_types = {'Active', 'Inactive'}
    value = updated_field_dict['status']
    if not value in available_status_types:
        return  '{SystemStatusTypeId is required and must be one of %s}' % (','.join(map(str,available_status_types)))

    value = updated_field_dict['organizationId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/organizations', 'name', value, auth_header)
        if not isGuid(guid): return '{organizationId is required}'
        else: updated_field_dict['organizationId'] = guid

    return json.dumps(updated_field_dict)

def verifyEnvironmentGuidFields(updated_fields_dict, auth_header):
    # 'sanity-check' name/id info & required fields

    value = updated_fields_dict['name']
    if value == None or isGuid(value):
        return '{Name is required}'

    value = updated_fields_dict['vendor']
    if value == None or isGuid(value):
        return '{Vendor is required}'

    value = updated_fields_dict['linkedSystemId']
    if value == None or not isGuid(value):
        guid = getOrGetGuidFromValue('/systems', 'name', value, auth_header)
        if isGuid(guid): updated_fields_dict['linkedSystemId'] = guid
        else: return '{LinkedSystemId is required}'

    value = updated_fields_dict['environmentStatusId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/lookupfields/EnvironmentStatus', 'value', value, auth_header)
        if isGuid(guid): updated_fields_dict['environmentStatusId'] = guid
        else: return '{EnvironmentStatusId is required}'

    value = updated_fields_dict['usageWorkItemId']
    if not isGuid(value):
        guid = getOrGetGuidFromValue('/lookupfields/UsedForWorkItem', 'value', value, auth_header)
        if isGuid(guid): updated_fields_dict['usageWorkItemId'] = guid
        else: return '{UsedForWorkItem is required}'

        if not isGuid(guid): return '{UsedForWorkItem is required}'
        else: updated_fields_dict['usageWorkItemId'] = guid

    value = updated_fields_dict['isSharedEnvironment']
    available_status_types = BinaryTrueFalse
    if not value in available_status_types:
        return  '{isSharedEnvironment is required and must be one of %s}' % (','.join(map(str, available_status_types)))
    else:
        value = eval(updated_fields_dict['isSharedEnvironment'])

    value = updated_fields_dict['color']
    if not isColor(value):
        return  '{Color is required and must be in the format #HHHHHH}'
    return json.dumps(updated_fields_dict)

def verifyChangesGuidFields(updated_field_values, auth_header):
    # 'sanity-check' name/id/addn'l info & required fields
    updated_field_values['additionalInformation'] = cleanseNullListAsString(updated_field_values['additionalInformation'] )

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
            return '{"createdsystem": {"name": %s, "id": %s}}' % (r.json()['name'], r.json()['id'])

    except:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

# Given the original values (and any we supplied in the GUI, verify consistency
# & go update the DB
def updateReleasePlutoraDB(starting_fields, updated_json_dict, is_copy, auth_header):
    pp = pprint.PrettyPrinter(indent=4)

    try:
        if is_copy:
            updated_json_dict['additionalInformation'] = cleanseNullListAsString(updated_json_dict['additionalInformation'])
            if 'OrderedDict' in updated_json_dict['additionalInformation']:
                updated_json_dict['additionalInformation'] = []

            mgrId = updated_json_dict['managerId']
            if not isGuid(mgrId):
                guid = getOrGetGuidFromValue('/users', 'userName', mgrId, auth_header)
                if isGuid(guid):
                    updated_json_dict['managerId'] = guid
                else:
                    return '{ManagerId is required}'

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
            return '{"createdrelease": { "name": %s, "id": %s}}' % (r.json()['name'], r.json()['id'])

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
            return '{"createdenvironment": {"name": %s, "id": %s}}' % (r.json()['name'], r.json()['id'])

    except:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

def updateChangesPlutoraDB(starting_fields, updated_json_dict, is_copy, auth_header):
    pp = pprint.PrettyPrinter(indent=4)

    try:
        if is_copy:
            updated_json_dict['stakeholders'] = cleanseNullListAsString(updated_json_dict['stakeholders'])
            updated_json_dict['additionalInformation'] = cleanseNullListAsString(updated_json_dict['additionalInformation'])
            # TODO: Must write something to handle this, eventually; for now, I'm just setting it to []
            if 'OrderedDict' in updated_json_dict['additionalInformation']:
                updated_json_dict['additionalInformation'] = []

            updated_json_dict['systems'] = cleanseNullListAsString(updated_json_dict['systems'])
            updated_json_dict['comments'] = cleanseNullListAsString(updated_json_dict['comments'])
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
            return '{"createdchange": { "name": %s, "id": %s}}' % (r.json()['name'], r.json()['id'])
    except:
        print "EXCEPTION: type: %s, msg: %s " % (sys.exc_info()[0],sys.exc_info()[1].message)
        exit('Error during API processing [POST]')

# given a list of dictionary elements, create a menu which allows updating.
class CreateMenu:
    def fetch(self):
        new_values = OrderedDict()
        for entry in self.entries:
            new_values[entry] = self.entries[entry].get()
        return new_values

    def makeform(self, parent, db_fields):
        parent.title("Send Updated Form to Plutora")
        self.fields = db_fields

        upper_frame = Frame(parent)
        upper_frame.pack(side=TOP)

        upper_top_label = Label(upper_frame, text="Update Plutora DB Record")
        upper_top_label.pack(side=TOP)

        quit_btn = Button(upper_frame, text="Done", command=parent.quit)
        quit_btn.pack(side=RIGHT)

        new_date_btn = Button(upper_frame, text="New Impl. Date", command=self.popup)
        new_date_btn.pack(side=RIGHT)

        lower_frame = Frame(parent)
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

    def popup(self):
        child = Toplevel()
        cal = DatePicker(child, self.data)

    def done(self):
        self.parent.kill()

    def __init__(self, db_fields, auth_header):
        self.data = {}
        self.auth_header = auth_header
        self.parent = Tk()
        self.entries = self.makeform(self.parent, db_fields)
        self.parent.mainloop()

def createRelease(use_gui, post_tgt_values_file, auth_header):
    try:
        with open(post_tgt_values_file) as json_data_file:
            org_fields = updated_fields = json.load(json_data_file, object_pairs_hook=OrderedDict)
        if use_gui:
            updated_fields = CreateMenu(org_fields, auth_header).fetch()

        return updateReleasePlutoraDB(org_fields, updated_fields, False, auth_header)

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

        return updateSystemPlutoraDB(org_fields, updated_fields, False, auth_header)

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

        return updateEnvironmentPlutoraDB(org_fields, updated_fields, False, auth_header)

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

        return updateChangesPlutoraDB(org_fields, updated_fields, False, auth_header)

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

        # Given a filename or guid-on-the-commandline, cycle through the different types of files (suffixes)
        # calling the appropriate createX routine.
        available_suffix_types = ['.rls', '.sys', '.env', '.chg']
        if post_tgt_values_file and len(filter(lambda k: k in post_tgt_values_file, available_suffix_types)) > 0:
            if '.sys' in post_tgt_values_file:
                print(createSystem(results.gui, post_tgt_values_file, authHeader))
            elif '.rls' in post_tgt_values_file:
                print(createRelease(results.gui, post_tgt_values_file, authHeader))
            elif '.env' in post_tgt_values_file:
                print(createEnvironment(results.gui, post_tgt_values_file, authHeader))
            elif '.chg' in post_tgt_values_file:
                print(createChanges(results.gui, post_tgt_values_file, authHeader))
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

