import os, sys, pytest, pandas, random
from pathlib import Path

# load local copy of libraries
sys.path.append(str( Path(Path(__file__).parents[1] / 'src').resolve() ))
from spaceandtime.spaceandtime import SXTUser


def test_remove_all_users_from_test_subscription():
    # login with admin
    admin = SXTUser(dotenv_file='.env_loader_admin')
    admin.authenticate()
    assert admin.user_id == 'testuser_owner'

    # get list of all users in subscription
    success, users = admin.get_subscription_users()
    assert success
    for userid, role in users.items():
        if userid == admin.user_id: continue # skip self

        # remove all other users from subscription
        success, response = admin.remove_from_subscription(userid)
        assert success

    success, users = admin.get_subscription_users()
    assert len(users) == 1


def test_adding_users_to_subscription():
    # login with admin 
    steve = SXTUser(dotenv_file='.env_loader_admin')
    steve.authenticate()
    assert steve.user_id == 'testuser_owner'

    sxtloader_users = []

    # create N new load users
    for i in range(0,5):

        # load keys, then override name
        sxtloaderN = SXTUser(dotenv_file='.env_loader',
                            user_id=f'testuser_joincode{i}_{str(random.randint(0,999999)).zfill(6)}',)
        assert 'disconnected' in sxtloaderN.subscription_id
        assert sxtloaderN.exists == False
        
        # register new user and add to subscription
        joincode = steve.generate_joincode(role='member')
        assert len(joincode) > 0

        success, response = sxtloaderN.register_new_user() 
        assert sxtloaderN.exists == True
        assert sxtloaderN.subscription_id == ''
        first_access_token = sxtloaderN.access_token

        if success: success, response = sxtloaderN.join_subscription(joincode)
        assert sxtloaderN.subscription_id != ''
        assert 'disconnected' not in sxtloaderN.subscription_id
        assert first_access_token != sxtloaderN.access_token

        success, response = sxtloaderN.leave_subscription()
        

if __name__ == '__main__':
    test_remove_all_users_from_test_subscription()
    test_adding_users_to_subscription()
    pass 