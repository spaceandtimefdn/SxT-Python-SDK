import os, sys, pytest, pandas, random
from dotenv import load_dotenv
from pathlib import Path

# load local copy of libraries
sys.path.append(str( Path(Path(__file__).parents[1] / 'src').resolve() ))
from spaceandtime.spaceandtime import SpaceAndTime
from spaceandtime.spaceandtime import SXTUser
from spaceandtime.sxtkeymanager import SXTKeyManager
from spaceandtime.sxtbiscuits import SXTBiscuit

API_URL = 'https://api.spaceandtime.app'


def test_sxt_wrapper():
    # pick up default .env file, with USERID="pySDK_tester"
    # note, that specific user must exist in .env this test to succeed.
    sxt = SpaceAndTime() 
    assert sxt.user.user_id == 'pySDK_tester'
    assert sxt.user.public_key == "Lu8fefHsAYxKfj7oaCx+Rtz7eNiPln6xbOxJJo0aIZQ="
    assert sxt.user.private_key[:6] == 'MeaW6J'

    assert len(sxt.access_token) == 0
    sxt.authenticate()
    assert len(sxt.access_token) > 0
    assert sxt.access_token[:4] == 'eyJ0' 
    assert sxt.user.user_id == 'pySDK_tester'

    success, data = sxt.execute_query('Select * from SXTLabs.Singularity limit 1')
    assert success
    assert data[0]['NAME'] == 'Singularity'
    assert type(data) == list
    assert type(data[0]) == dict

    # pick up specific .env file, with USERID="sxtlabs.crm.etl"
    # note, that specific user must exist for this test to succeed.
    sxt = SpaceAndTime(envfile_filepath='./.env_crm') 
    assert sxt.user.user_id == 'sxtlabs.crm.etl'
    assert sxt.user.public_key == "iGuRWoH7SMKrvDArfRAoWadMNIPCgJpzgkuK0mM1cFU="
    assert sxt.user.private_key[:6] == 'KMua+5'

    assert len(sxt.access_token) == 0
    sxt.authenticate()
    assert len(sxt.access_token) > 0

    success, data = sxt.execute_query('Select * from SXTLabs.Singularity limit 1')
    assert success
    assert data[0]['NAME'] == 'Singularity'

    # define specific outside of .env, in memory only
    userid = 'testuser_X_' + f"{random.randint(0,999999999999):012}"
    keypair = SXTKeyManager(new_keypair=True, encoding=sxt.ENCODINGS.BASE64)

    sxt = SpaceAndTime(api_url=API_URL, user_id=userid, user_private_key=keypair.private_key)
    assert sxt.user.user_id == userid
    assert sxt.user.private_key == keypair.private_key
    sxt.authenticate()

    success, data = sxt.execute_query('Select * from SXTLabs.Singularity limit 1')
    assert success
    assert data[0]['NAME'] == 'Singularity'

    
def test_sxt_user():
    # pick up default .env file, with USERID="pySDK_tester"
    # note, that specific user must be used for this test to succeed.
    sxt = None

    # UserA -- load .env file
    userA = SXTUser(dotenv_file='./.env')
    assert userA.user_id == 'pySDK_tester'
    assert userA.public_key == "Lu8fefHsAYxKfj7oaCx+Rtz7eNiPln6xbOxJJo0aIZQ="
    assert userA.private_key[:6] == 'MeaW6J'

    assert len(userA.access_token) == 0
    userA.authenticate()
    assert len(userA.access_token) > 0
    assert userA.access_token[:4] == 'eyJ0' 
    assert userA.user_id == 'pySDK_tester'

    success, data = userA.execute_query("Select Name, 'A' as UserLetter from SXTLabs.Singularity limit 1")
    assert success
    assert data[0]['NAME'] == 'Singularity'
    assert data[0]['USERLETTER'] == 'A'

    # UserB -- load specific info
    userid = 'testuser_X_' + f"{random.randint(0,999999999999):012}"
    keypair = SXTKeyManager(new_keypair=True)
    userB = SXTUser(user_id=userid, user_private_key=keypair.private_key, api_url=API_URL, authenticate=True)
    success, data = userB.execute_query("Select Name, 'B' as UserLetter from SXTLabs.Singularity limit 1")
    assert success
    assert data[0]['NAME'] == 'Singularity'
    assert data[0]['USERLETTER'] == 'B'

    # Alternate querying with different users
    success, data = userA.execute_query("Select Name, 'A' as UserLetter from SXTLabs.Singularity limit 1")
    assert success
    success, data = userB.execute_query("Select Name, 'B' as UserLetter from SXTLabs.Singularity limit 1")
    assert success
    success, data = userA.execute_query("Select Name, 'A' as UserLetter from SXTLabs.Singularity limit 1")
    assert success
    success, data = userB.execute_query("Select Name, 'B' as UserLetter from SXTLabs.Singularity limit 1")
    assert success

    assert userA.user_id != userB.user_id
    assert userA.access_token != userB.access_token

    # this is just for backwards compatibility... prefer not to use:
    success, data = userA.execute_sql("Select Name, 'A' as UserLetter from SXTLabs.Singularity limit 1")
    assert success
    assert data[0]['NAME'] == 'Singularity'
    assert data[0]['USERLETTER'] == 'A'

    # test secret testuser functionality
    userC = SXTUser(testuser='C', user_private_key=keypair.private_key, api_url=API_URL, authenticate=True)
    success, data = userC.execute_sql("Select Name, 'C' as UserLetter from SXTLabs.Singularity limit 1")
    assert success
    assert data[0]['NAME'] == 'Singularity'
    assert data[0]['USERLETTER'] == 'C'

 
def test_execute_query():
    sxt = SpaceAndTime()
    sxt.authenticate()
    success, data = sxt.execute_query('Select * from SXTLabs.Singularity limit 1')
    assert success
    assert data[0]['NAME'] == 'Singularity'
    assert type(data) == list
    assert type(data[0]) == dict

    success, data = sxt.execute_query('Select * from SXTLabs.Singularity limit 1', 
                                      sql_type=sxt.SQLTYPE.DQL, resources=['SXTLabs.Singularity'],
                                      output_format = sxt.OUTPUT_FORMAT.PARQUET )
    assert success
    assert type(data) == bytes
 
    success, data = sxt.execute_query('Select * from SXTLabs.Singularity limit 1', 
                                      sql_type=sxt.SQLTYPE.DQL, resources=['SXTLabs.Singularity'],
                                      output_format = sxt.OUTPUT_FORMAT.DATAFRAME )
    assert success
    assert type(data) == pandas.DataFrame

    success, data = sxt.execute_query('Select * from SXTLabs.Singularity limit 1', 
                                      sql_type=sxt.SQLTYPE.DQL, resources=['SXTLabs.Singularity'],
                                      output_format = sxt.OUTPUT_FORMAT.CSV )
    assert success
    assert type(data) == list
    assert type(data[0]) == str # header
    assert type(data[1]) == str # data
    assert len(data) == 2 # header + 1 data row
    assert data[1].count(',') > 3


def test_discovery():
    sxt = SpaceAndTime()
    sxt.authenticate()

    # Schemas
    success, schemas = sxt.discovery_get_schemas(return_as=list)
    assert success
    assert type(schemas) == list 
    assert 'ETHEREUM' in schemas
    assert 'SXTDEMO' in schemas
    assert 'SXTLABS' in schemas

    success, schemas = sxt.discovery_get_schemas(return_as=dict)
    assert success
    assert type(schemas) == list
    assert type(schemas[0]) == dict
    assert [s for s in schemas if s['schema']=='SXTDEMO'][0]['isPublic']

    success, schemas = sxt.discovery_get_schemas(return_as=str)
    assert success
    assert type(schemas) == str
    assert 'POLYGON,' in schemas
    assert schemas.count(',') >= 10

    success, schemas = sxt.discovery_get_schemas(scope = sxt.DISCOVERY_SCOPE.PRIVATE)
    assert success
    assert schemas.count(',') == 0  # no such thing right now

    # Tables
    success, tables = sxt.discovery_get_tables('SXTLabs', scope = sxt.DISCOVERY_SCOPE.PRIVATE, return_as=list)
    assert success
    assert 'SXTLABS.CRM_ACCOUNTS' in tables
    assert len(tables) >=10

    success, tables = sxt.discovery_get_tables('SXTLabs', search_pattern='CRM_Cosell', scope = sxt.DISCOVERY_SCOPE.PRIVATE, return_as=list)
    assert success
    assert 'SXTLABS.CRM_COSELL_AGREEMENTS' in tables
    assert len(tables) <=10

    # Columns
    success, columns = sxt.discovery_get_table_columns('POLYGON', 'BLOCKS', return_as=list)
    assert success
    assert 'TIME_STAMP' in columns
    assert len(columns) > 5
    
    success, columns = sxt.discovery_get_table_columns('POLYGON', 'BLOCKS', search_pattern='BLOCK', return_as=dict)
    assert success
    assert 'BLOCK_NUMBER' in [c['column'] for c in columns]
    assert len(columns) < 5
    


if __name__ == '__main__':
    
    test_execute_query()
    test_access_token_created()
    test_execute_query()
    test_discovery()
    pass 