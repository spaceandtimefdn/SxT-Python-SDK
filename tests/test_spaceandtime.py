import os, sys, pytest, pandas, random, json
from pathlib import Path
from datetime import datetime

# load local copy of libraries
sys.path.append(str( Path(Path(__file__).parents[1] / 'src').resolve() ))
from spaceandtime.spaceandtime import SpaceAndTime
from spaceandtime.spaceandtime import SXTUser
from spaceandtime.sxtkeymanager import SXTKeyManager
from spaceandtime.sxtbiscuits import SXTBiscuit
from spaceandtime.sxtexceptions import *  # only contains exceptions prefixed with "SXT"
API_URL = 'https://api.makeinfinite.dev'

def setup_debug_logger():
    import logging
    logfile = Path(Path(__file__).resolve().parent / 'logs'/ f"pytest_debug_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.log")
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    if len(logger.handlers) == 0: 
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        formatter.default_time_format = '%Y-%m-%d %H:%M:%S'
        formatter.default_msec_format = '%s.%03d'
        # file handler:
        file_handler = logging.FileHandler(logfile)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        # console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    return logger

mylogger = setup_debug_logger()

def test_sxt_addfilehandler():
    logfilepath =  Path(Path(__file__).parent / 'logs' / 'test_sxt_addfilehandler.log')
    sxt = SpaceAndTime()

    for test in [logfilepath, str(logfilepath)]:
        logfilepath.unlink(missing_ok=True)
        assert not logfilepath.exists()
        sxt.logger_addFileHandler(test)
        sxt.logger.info('test message')
        assert logfilepath.exists()
        sxt.logger.handlers.clear()



def test_sxt_exceptions():
    mylogger.info(f'\n\ntest_sxt_exceptions\n{"-"*30}')
    # test common exceptions
    sxt = SpaceAndTime() 
    sxt.user.user_id = sxt.user.api_key = ''
    with pytest.raises(Exception) as e_info: sxt.authenticate()

    sxt = SpaceAndTime() 
    sxt.user.private_key = sxt.user.api_key = ''
    with pytest.raises(Exception) as e_info: sxt.authenticate()

    with pytest.raises(SxTAuthenticationError) as errinfo:   raise SxTAuthenticationError('test message: SxTAuthenticationError')
    with pytest.raises(SxTQueryError) as errinfo:            raise SxTQueryError('test message: SxTQueryError')
    with pytest.raises(SxTFileContentError) as errinfo:      raise SxTFileContentError('test message: SxTFileContentError')
    with pytest.raises(SxTArgumentError) as errinfo:         raise SxTArgumentError('test message: SxTArgumentError')
    with pytest.raises(SxTKeyEncodingError) as errinfo:      raise SxTKeyEncodingError('test message: SxTKeyEncodingError')
    with pytest.raises(SxTBiscuitError) as errinfo:          raise SxTBiscuitError('test message: SxTBiscuitError')
    with pytest.raises(SxTAPINotDefinedError) as errinfo:    raise SxTAPINotDefinedError('test message: SxTAPINotDefinedError')
    with pytest.raises(SxTAPINotSuccessfulError) as errinfo: raise SxTAPINotSuccessfulError('test message: SxTAPINotSuccessfulError')


def test_sxt_wrapper():
    mylogger.info(f'\n\ntest_sxt_wrapper\n{"-"*30}')
    # pick up default .env file, with USERID="pySDK_tester" or... testuser_977604126 ?
    # note, that specific user must exist in .env this test to succeed.
    envfile = Path(Path(__file__).parents[1] / '.env').resolve()
    sxt = SpaceAndTime(envfile_filepath = envfile, logger= setup_debug_logger() )
    sxt.user.user_id = 'pySDK_tester'
    assert sxt.user.user_id == 'pySDK_tester'
    assert sxt.user.public_key == "Lu8fefHsAYxKfj7oaCx+Rtz7eNiPln6xbOxJJo0aIZQ="
    assert sxt.user.private_key[:6] == 'MeaW6J'

    assert len(sxt.access_token) == 0
    assert sxt.user.subscription_id == None
    assert sxt.user.is_quota_exceeded == None
    assert sxt.user.is_restricted == None
    assert sxt.user.is_trial == None
    sxt.authenticate()
    assert len(sxt.access_token) > 0
    assert sxt.user.subscription_id != None
    assert sxt.user.is_quota_exceeded != None
    assert sxt.user.is_restricted != None
    assert sxt.user.is_trial != None
    assert sxt.access_token[:4] == 'eyJ0' 
    assert sxt.user.user_id == 'pySDK_tester'

    success, data = sxt.execute_query('Select * from SXTLabs.Singularity limit 1')
    assert success
    assert data[0]['NAME'] == 'Singularity'
    assert type(data) == list
    assert type(data[0]) == dict
  
    
def test_sxt_user():
    mylogger.info(f'\n\ntest_sxt_user\n{"-"*30}')
    # pick up default .env file, with USERID="pySDK_tester"
    # note, that specific user must be used for this test to succeed.
    print('test_sxt_user')
    sxt = None

    # UserA -- load .env file
    userA = SXTUser(dotenv_file='./.env', api_url=API_URL, logger= setup_debug_logger() )
    assert userA.user_id == 'pySDK_tester'
    assert userA.public_key == "Lu8fefHsAYxKfj7oaCx+Rtz7eNiPln6xbOxJJo0aIZQ="
    assert userA.private_key[:6] == 'MeaW6J'

    assert len(userA.access_token) == 0
    userA.authenticate()
    assert len(userA.access_token) > 0
    assert userA.access_token[:4] == 'eyJ0' 

    success, data = userA.execute_query("Select Name, 'A' as UserLetter from SXTLabs.Singularity limit 1")
    assert success
    assert data[0]['NAME'] == 'Singularity'
    assert data[0]['USERLETTER'] == 'A'


    # UserB -- load alternate .env file
    userB = SXTUser(dotenv_file='./.env_alt', api_url=API_URL, authenticate=True, logger= setup_debug_logger() )
    # assert userB.user_id == 'pySDK_tester2'
    # assert userB.public_key == "Lu8fefHsAYxKfj7oaCx+Rtz7eNiPln6xbOxJJo0aIZQ="
    # assert userB.private_key[:6] == 'MeaW6J'
    assert userB.user_id == 'stephen_cli'
    assert userB.public_key == "S4HCEEe5Hlp0ePANRkNF7xrb3zasKz87H9QQ5ZcT9fU="
    assert userB.private_key[:6] == 'z0STaV'

    # authenticate flag used in initializer
    assert len(userB.access_token) > 0
    assert userB.access_token[:4] == 'eyJ0' 

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

    # assert userA.user_id != userB.user_id
    # assert userA.access_token != userB.access_token

    # this is just for backwards compatibility... prefer not to use:
    success, data = userA.execute_sql("Select Name, 'A' as UserLetter from SXTLabs.Singularity limit 1")
    assert success
    assert data[0]['NAME'] == 'Singularity'
    assert data[0]['USERLETTER'] == 'A'



def test_sxt_user_2():
    mylogger.info(f'\n\ntest_sxt_user_2\n{"-"*30}')
    # pick up default .env file, with USERID="pySDK_tester"
    # note, that specific user must be used for this test to succeed.
    print('test_sxt_user')
    sxt = None

    # UserA -- load .env file
    userA = SXTUser(dotenv_file='./.env', api_url=API_URL, logger= setup_debug_logger() )
    assert userA.user_id == 'pySDK_tester'
    assert userA.public_key == "Lu8fefHsAYxKfj7oaCx+Rtz7eNiPln6xbOxJJo0aIZQ="
    assert userA.private_key[:6] == 'MeaW6J'

    assert len(userA.access_token) == 0
    userA.authenticate()
    assert len(userA.access_token) > 0
    assert userA.access_token[:4] == 'eyJ0' 

    success, data = userA.execute_query("Select Name, 'A' as UserLetter from SXTLabs.Singularity limit 1")
    assert success
    assert data[0]['NAME'] == 'Singularity'
    assert data[0]['USERLETTER'] == 'A'


    # UserB -- load alternate .env file
    userB = userA # SXTUser(dotenv_file='./.env_alt', api_url=API_URL, authenticate=True, logger= setup_debug_logger() )
    # assert userB.user_id == 'pySDK_tester2'
    assert userB.public_key == "Lu8fefHsAYxKfj7oaCx+Rtz7eNiPln6xbOxJJo0aIZQ="
    assert userB.private_key[:6] == 'MeaW6J'

    # authenticate flag used in initializer
    assert len(userB.access_token) > 0
    assert userB.access_token[:4] == 'eyJ0' 

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

    # assert userA.user_id != userB.user_id
    # assert userA.access_token != userB.access_token

    # this is just for backwards compatibility... prefer not to use:
    success, data = userA.execute_sql("Select Name, 'A' as UserLetter from SXTLabs.Singularity limit 1")
    assert success
    assert data[0]['NAME'] == 'Singularity'
    assert data[0]['USERLETTER'] == 'A'


 
def test_execute_query():
    mylogger.info(f'\n\ntest_execute_query\n{"-"*30}')
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
    mylogger.info(f'\n\ntest_discovery\n{"-"*30}')
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
    assert type(schemas) == dict

    success, schemas = sxt.discovery_get_schemas(return_as=str)
    assert success
    assert type(schemas) == str
    assert 'POLYGON,' in schemas
    assert schemas.count(',') >= 10

    success, all_schemas = sxt.discovery_get_schemas(scope = sxt.DISCOVERY_SCOPE.ALL)
    assert success
    success, sub_schemas = sxt.discovery_get_schemas(scope = sxt.DISCOVERY_SCOPE.SUBSCRIPTION)
    assert success
    assert len(all_schemas) > len(sub_schemas)

    # Tables
    success, tables = sxt.discovery_get_tables('SXTLabs', scope = sxt.DISCOVERY_SCOPE.SUBSCRIPTION, return_as=list)
    assert success
    assert 'SXTLABS.CRM_ACCOUNTS' in tables
    assert len(tables) >=10

    success, tables = sxt.discovery_get_tables('SXTLabs', search_pattern='CRM_Cosell', scope = sxt.DISCOVERY_SCOPE.SUBSCRIPTION, return_as=list)
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
    assert 'BLOCK_NUMBER' in columns.keys()
    assert len(columns) < 5
    
    success, columns = sxt.discovery_get_table_columns('SXTLABS', 'CRM_ACCOUNTS') # defaults to dict
    assert success
    assert 'CREATED_TIME' in columns.keys()
    assert 'ACCOUNT_NAME' in columns.keys()
    assert len(columns) > 15

    success, views = sxt.discovery_get_views('SXTLabs', scope = sxt.DISCOVERY_SCOPE.ALL, return_as=list)
    assert success
    assert len(views) > 0
    assert type(views[0]) == str

    success, views = sxt.discovery_get_views('SXTLabs', return_as=json)
    assert success
    assert len(views) > 0
    assert type(views) == str
    jsonreturn = json.loads(views)
    assert type(jsonreturn) == dict
    assert jsonreturn[list(jsonreturn.keys())[0]]['schema'].upper() == 'SXTLABS'


if __name__ == '__main__':
    # test_sxt_addfilehandler()
    # test_sxt_exceptions()
    # test_sxt_wrapper()
    # test_sxt_user_2()
    # test_sxt_user()
    # test_execute_query()
    # test_discovery()

    # logger = setup_debug_logger()
    # logger.info('\n\nDone!!!')
    pass 