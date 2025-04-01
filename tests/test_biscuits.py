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




km = SXTKeyManager(new_keypair=True)
my_private_key = km.private_key


from spaceandtime import SXTBiscuit, SXTTable

mytable = SXTTable('schema.myTable', private_key=my_private_key)
mytable.add_biscuit('Admin', SXTBiscuit.GRANT.ALL)


