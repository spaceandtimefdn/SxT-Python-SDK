import os, sys, pytest, pandas, random
from pathlib import Path

# load local copy of libraries
sys.path.append(str( Path(Path(__file__).parents[1] / 'src').resolve() ))
from spaceandtime.spaceandtime import SpaceAndTime
from spaceandtime.spaceandtime import SXTUser
API_URL = 'https://api.spaceandtime.dev'




# create test file:
def create_random_test_file(skip_pos: int = None):
    rndnum = random.randint(1,1e9)
    filepaths = []
    for iloop, testsetup in enumerate( ['USER', 'SXT_USER', 'USER_', 'SXT_USER_'] ):
        filepath = Path(f'./tests/user_saves/{testsetup}--test.{rndnum}.env')
        filecontent = [f'API_URL=https://api.spaceandtime.dev\n']
        if iloop != skip_pos: 
            filecontent.append(f'{testsetup}ID=testuser_{rndnum}\n')
            filecontent.append(f'{testsetup}_PRIVATE_KEY=Z833BwZcwotJf4zVA89HlyvxH8xqAUOXzTcR1dWhsrk=\n')
            filecontent.append(f'{testsetup}_PUBLIC_KEY=Z833BwZcwotJf4zVA89HlyvxH8xqAUOXzTcR1dWhsrk=\n')
        filecontent = str(''.join(filecontent)).replace('__','_')
        with open(filepath, 'w') as f:
            f.write(filecontent)
        filepaths.append(filepath)
    return rndnum, filepaths


    
def test_random_user_envars():

    for skiptest in [None, 0, 1, 2, 3]:

        # create new login .env file
        rndnum, envfilepaths = create_random_test_file(skiptest)

        # load new .env file 
        for iloop, envfilepath in enumerate(envfilepaths):
            if iloop == skiptest: continue
            sxt = None 
            os.environ.clear()
            with open(envfilepath, 'r') as f:
                print(f.read())
            sxt = SpaceAndTime(envfile_filepath = envfilepath)
            assert sxt.user.user_id == f'testuser_{rndnum}'
            assert sxt.user.private_key == 'Z833BwZcwotJf4zVA89HlyvxH8xqAUOXzTcR1dWhsrk='
            

 
test_random_user_envars()
