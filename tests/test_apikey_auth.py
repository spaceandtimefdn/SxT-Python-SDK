import os, sys
from pathlib import Path
from datetime import datetime
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


def test_apikey_login():
    
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

    # execute test query
    success, data = sxt.execute_query(biscuits=[SXTLABS_BISCUIT, SXT_STATE_BISCUIT], 
                                      sql_text="""Select * from sxtlabs.singularity""")
    assert success
    assert len(data) == 1

 
if __name__ == "__main__":
    test_apikey_login()
    pass