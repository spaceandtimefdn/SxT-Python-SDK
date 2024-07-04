import os, sys, pytest, pandas, random
from pathlib import Path

# load local copy of libraries
sys.path.append(str( Path(Path(__file__).parents[1] / 'src').resolve() ))
from spaceandtime.spaceandtime import SpaceAndTime
from spaceandtime.spaceandtime import SXTUser
from spaceandtime.sxtkeymanager import SXTKeyManager
from spaceandtime.sxtbiscuits import SXTBiscuit
from spaceandtime.sxtexceptions import *  # only contains exceptions prefixed with "SXT"
API_URL = 'https://api.spaceandtime.app'


def test_user_save_load_bug():
    my_userid = f"testuser_pytest1_{random.randint(0,1e18):018}" # make random userid

    # create user (local only, not on SXT network) and save file:
    usr1 = SXTUser(user_id=my_userid, new_keypair=True, encoding=SXTUser.ENCODINGS.HEX)
    assert usr1.user_id == my_userid
    assert len(usr1.private_key) == 64
    assert len(usr1.public_key) == 64
    assert usr1.api_url == API_URL

    save_filename = Path(f'./tests/user_saves/{usr1.user_id}.env')
    usr1.save(save_filename)
    assert save_filename.exists()

    # create another user, loaded from above file 
    usr2 = SXTUser(dotenv_file=f'./tests/user_saves/{usr1.user_id}.env')
    assert usr2 != usr1
    assert str(usr2) == str(usr1)
    assert usr2.user_id == usr1.user_id
    assert usr2.private_key == usr1.private_key
    assert usr2.public_key == usr1.public_key
    assert usr2.api_url == usr1.api_url
    
    # create third user, loaded from above file 
    usr3 = SXTUser()
    usr3.load(f'./tests/user_saves/{usr1.user_id}.env')
    assert usr3 != usr1
    assert str(usr3) == str(usr1)
    assert usr3.user_id == usr1.user_id
    assert usr3.private_key == usr1.private_key
    assert usr3.public_key == usr1.public_key
    assert usr3.api_url == usr1.api_url
    
    pass 




if __name__ == '__main__':
    test_user_save_load_bug()