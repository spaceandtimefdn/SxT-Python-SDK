import os, sys, pytest, pandas, random
from pathlib import Path
from datetime import datetime
from pprint import pprint
from dotenv import load_dotenv

# load local copy of libraries
sys.path.append(str( Path(Path(__file__).parents[1] / 'src').resolve() ))
from spaceandtime.spaceandtime import SpaceAndTime
from spaceandtime.spaceandtime import SXTUser
from spaceandtime.sxtkeymanager import SXTKeyManager
from spaceandtime.sxtbiscuits import SXTBiscuit
from spaceandtime.sxtexceptions import *  # only contains exceptions prefixed with "SXT"

ENV = Path(Path(__file__).parents[1] / '.env')
load_dotenv(ENV, override=True)

API_URL = os.getenv('API_URL')
USER_API_KEY = os.getenv('USER_API_KEY')
SXT_STATE_BISCUIT = os.getenv('SXT_STATE_BISCUIT')    
SXTLABS_BISCUIT   = os.getenv('SXTLABS_BISCUIT')  
SXT_TELEM_BISCUIT = os.getenv('SXT_TELEM_BISCUIT')    

 

def _est_telem_queries_in_schemas():
    schemas = ['sui','sxtlabs','ethereum']
    days = 14

    # authenticate with API Key, throwing env file location off:
    sxt = SpaceAndTime()
    sxt.user.private_key = ''
    sxt.user.public_key = ''
    sxt.user.user_id = ''
    
    sxt.user.api_key = USER_API_KEY
    sxt.authenticate()

    assert sxt.user.user_id == 'pySDK_tester'
    assert not sxt.user.access_expired
    assert sxt.user.exists
    assert not sxt.user.is_trial
    assert not sxt.user.is_quota_exceeded
    assert not sxt.user.is_restricted
    assert len(sxt.access_token) > 0
    assert len(sxt.user.subscription_id) > 0
    assert sxt.user.public_key == ''
    assert sxt.user.private_key == '' 

    # run thru schema queries
    all_queries = []
    for schema in schemas:
        sxt.logger.info(f'\n\nProcessing {schema} for the last {days} days\n{"-"*30}')
        
        schema_queries = []
        sql = f"""
        Select 
          '{schema.strip()}' as Schema_Name 
        , coalesce(a.Account_Name,'Not Registered') as Sub_Name
        , count(distinct c.Subscription_ID) as Sub_Count
        , count(distinct c.USER_ID) as User_Count
        , count(*) as Queries
        , max(timestamp) as max_timestamp
        , min(timestamp) as min_timestamp
        , max(c.USER_ID) as max_UserID
        , min(c.USER_ID) as min_UserID
        FROM SXT_STATE.QUERY_META_CORE as c 
        left outer join SXTLabs.CRM_Accounts as a
        on c.Subscription_ID = a.Subscription_ID
        WHERE c.SQL_Text ilike '%{ schema.strip() }.%'
          and cast(timestamp as date) > current_date - {days}
          and c.USER_ID not in('pySDK_tester','stephen')
        group by 1,2 order by 2 desc
        """
        success, schema_queries = sxt.execute_query(sql, biscuits=[SXTLABS_BISCUIT, SXT_STATE_BISCUIT] )
        assert success

        all_queries = all_queries + schema_queries

    assert len(all_queries) == len(schemas)
    pprint(all_queries)
    pass 

    

if __name__ == "__main__":
    # test_telem_queries_in_schemas()
    pass