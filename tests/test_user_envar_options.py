import os, sys, pytest, pandas, random
from pathlib import Path

# load local copy of libraries
sys.path.append(str( Path(Path(__file__).parents[1] / 'src').resolve() ))
from spaceandtime.spaceandtime import SpaceAndTime, SXTUser


# create test file:
def create_random_test_file():
    rndnum = random.randint(1,1e9)
    filepaths = []
    for testsetup in ['USER', 'SXT_USER', 'USER_', 'SXT_USER_']:
        filepath = Path(f'./tests/user_saves/{testsetup}--test.{rndnum}.env')
        filecontent = [f'API_URL=https://api.spaceandtime.dev\n']
        filecontent.append(f'{testsetup}ID=testuser_{rndnum}\n')
        filecontent.append(f'{testsetup}_PRIVATE_KEY=Z833BwZcwotJf4zVA89HlyvxH8xqAUOXzTcR1dWhsrk=\n')
        filecontent.append(f'{testsetup}_PUBLIC_KEY=Z833BwZcwotJf4zVA89HlyvxH8xqAUOXzTcR1dWhsrk=\n')
        filecontent = str(''.join(filecontent)).replace('__','_')
        with open(filepath, 'w') as f:
            f.write(filecontent)
        filepaths.append(filepath)
    return rndnum, filepaths


    
def test_remove_all_users_from_test_subscription():

    # create new login .env file
    rndnum, envfilepaths = create_random_test_file()

    # load new .env file 
    for envfilepath in envfilepaths:
        sxt = SpaceAndTime(envfile_filepath = envfilepath)
        assert sxt.user.user_id == f'testuser_{rndnum}'
        assert sxt.user.private_key == 'Z833BwZcwotJf4zVA89HlyvxH8xqAUOXzTcR1dWhsrk='
        sxt = None 

 
test_remove_all_users_from_test_subscription()
