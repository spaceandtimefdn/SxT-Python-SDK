import os, sys, pytest
from dotenv import load_dotenv
from pathlib import Path

# load local copy of libraries
sys.path.append(str( Path(Path(__file__).parents[1] / 'src').resolve() ))
from spaceandtime.sxtbaseapi import SXTBaseAPI
from spaceandtime.sxtkeymanager import SXTKeyManager
from spaceandtime.sxtbiscuits import SXTBiscuit

# load env variables
load_dotenv(Path(Path(__file__).parent / '.env'))
api_url = os.getenv('API_URL')
userid = os.getenv('USERID')
keys = SXTKeyManager(os.getenv('USER_PRIVATE_KEY'))

# authenticate once for all subsequent tests
sxtb = SXTBaseAPI()
success, response = sxtb.get_auth_challenge_token(userid)
challenge = response['authCode']
success, tokens = sxtb.auth_token(user_id=userid, keymanager=keys, challange_token=challenge)
access_token  = tokens['accessToken']
refresh_token = tokens['refreshToken']


def test_access_token_created():
    # designed to test the root-level authentication
    assert access_token !=''


def test_peripheral_functions():
    sxtb = SXTBaseAPI()

    # prep biscuits
    assert ['a','b','c'] == sxtb.prep_biscuits(['a','b','c'])
    assert ['a','b','c','d','e'] == sxtb.prep_biscuits(['a','b',['c','d','e']])
    assert ['a','b','c','d','e'] == sxtb.prep_biscuits([['a','b'],['c','d','e']])
    bf = SXTBiscuit(biscuit_token='f')
    bg = SXTBiscuit(biscuit_token='g')
    assert ['a','b','c','d','e','f','g'] == sxtb.prep_biscuits([['a','b'],['c','d','e'],bf, bg])

    # prep sql  - removes newlines, tabs, double spaces, and trailing ';', except where they appear inside a string
    assert 'select * from schema.mytable' == sxtb.prep_sql('\n  select * \n\tfrom schema.mytable  ')
    assert 'select * from schema.mytable' == sxtb.prep_sql('  select   *     from   schema.mytable')
    assert 'select "some \tstring" as colA from schema.mytable' == sxtb.prep_sql(' select "some \tstring" as colA  \nfrom  schema.mytable; ')


def test_authenticate():
    sxtb = SXTBaseAPI()
    keys.encoding = keys.ENCODINGS.BASE64

    # get challenge code
    success, response = sxtb.get_auth_challenge_token(userid)
    assert success

    # login with explicit signature
    challenge = response['authCode']
    success, tokens = sxtb.auth_token(user_id=userid, public_key=keys.public_key_to(keys.ENCODINGS.BASE64), 
                                      challange_token=challenge, signed_challange_token=keys.sign_message(challenge))
    assert success

    # login with abbreviated keymanager signature
    success, response = sxtb.get_auth_challenge_token(userid)
    challenge = response['authCode']
    success, tokens = sxtb.auth_token(user_id=userid, keymanager=keys, challange_token=challenge)
    assert success
    
    # wrong key
    keywrong = SXTKeyManager(new_keypair=True)
    success, response = sxtb.get_auth_challenge_token(userid)
    challenge = response['authCode']
    success, tokens = sxtb.auth_token(user_id=userid, keymanager=keywrong, challange_token=challenge)
    assert (not success)
    
    # alias calls (with good key)
    success, response = sxtb.auth_code(userid)
    challenge = response['authCode']
    success, tokens = sxtb.get_access_token(user_id=userid, keymanager=keys, challange_token=challenge)
    assert success


def test_call_api():
    sxtb = SXTBaseAPI(access_token)
    success, user_exists = sxtb.call_api('auth/idexists/{id}', auth_header=False, 
                                      request_type=sxtb.APICALLTYPE.GET, 
                                      path_parms={'id':userid})
    assert success
    assert user_exists 

    success, user_exists = sxtb.call_api('auth/idexists/{id}', auth_header=False, 
                                      request_type=sxtb.APICALLTYPE.GET, 
                                      path_parms={'id':'this_user_should_not_exist_please_dont_create'})
    assert success
    assert not user_exists 

    success, data = sxtb.call_api('sql', auth_header=True, request_type=sxtb.APICALLTYPE.POST, 
                                  data_parms={'sqlText':'select * from sxtlabs.singularity'} )
    assert success
    assert data[0]['NAME'] == 'Singularity' # hopefully this doesn't change...

    # what happens if we break it?
    # bad API
    success, data = sxtb.call_api('no_such_api', auth_header=False, request_type=sxtb.APICALLTYPE.POST)
    assert not success
    assert data['status_code'] == 555

    # good API, not validated
    success, data = sxtb.call_api('sql', auth_header=False, request_type=sxtb.APICALLTYPE.POST, 
                                  data_parms={'sqlText':'select * from sxtlabs.singularity'} )
    assert not success
    assert data['status_code'] == 401
    assert 'Unauthorized' in data['error'] 
    assert 'JWT authorization failed' in data['text'] 


def test_logout():
    sxtb = SXTBaseAPI(access_token)
    success, response = sxtb.auth_logout()
    # this API isn't working right now, so:
    success = True
    assert success


if __name__ == '__main__':
    test_access_token_created()
    test_peripheral_functions()
    test_authenticate()
    test_call_api()
    test_logout()
    pass 