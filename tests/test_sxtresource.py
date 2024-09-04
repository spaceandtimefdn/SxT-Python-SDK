import os, sys, pytest, pandas, random
from dotenv import load_dotenv
from pathlib import Path

# load local copy of libraries
sys.path.append(str( Path(Path(__file__).parents[1] / 'src').resolve() ))
from spaceandtime.spaceandtime import SpaceAndTime
from spaceandtime.spaceandtime import SXTUser
from spaceandtime.sxtkeymanager import SXTKeyManager
from spaceandtime.sxtresource import SXTResource, SXTTable
from spaceandtime.sxtbiscuits import SXTBiscuit

API_URL = 'https://api.spaceandtime.app'


def test_resource_save_load_bug():
    sxt = SpaceAndTime()
    sxt.authenticate()

    tbl = SXTTable('SXTTemp.test_save_load', private_key=os.getenv('RESOURCE_PRIVATE_KEY'), SpaceAndTime_parent=sxt)
    tbl.add_biscuit('admin', sxt.GRANT.ALL)
    tbl.create_ddl = """
    CREATE TABLE {table_name} 
    ( MyID         int
    , MyName       varchar
    , MyNumber     int
    , Primary Key  (MyID) 
    ) {with_statement} 
    """
    assert tbl.save() # saved correctly?
    tbl2 = SXTTable(from_file = tbl.recommended_filename)
    assert tbl2.private_key == tbl.private_key
    assert tbl2.create_ddl == tbl.create_ddl
    assert tbl2.table_name == tbl.table_name




def test_resource_methods():
    keys = SXTKeyManager(new_keypair=True)
    rs = SXTResource('Test')
    userA = SXTUser(testuser='A', user_private_key=keys.private_key)
    userB = SXTUser(testuser='B', user_private_key=keys.private_key)
    userE = SXTUser(testuser='E')
    userE.key_manager = SXTKeyManager()
    userO = object()
    userS = 'just a string, man'
    userRS = SXTUser(testuser='RS', user_private_key=keys.private_key)
    rs.user = userRS 

    assert rs.get_first_valid_user(userO, userS, userE, userA, userB) == userA
    assert rs.get_first_valid_user(userS, userB, userA, userE) == userB
    assert rs.get_first_valid_user(userA, userB, userO, userS) == userA
    assert rs.get_first_valid_user(userS, userRS, userB, userA, userO) == userRS
    assert rs.get_first_valid_user() == userRS

    assert rs.get_first_valid_user(userE, userS) == userRS
    rs.user = userO
    assert rs.get_first_valid_user(userE, userS) == userE
    assert rs.get_first_valid_user(userS, userO) == None

 
def test_inserts_deletes_updates():
    sxt = SpaceAndTime()
    sxt.authenticate()

    tbl = SXTTable(name='SXTTemp.Test_DML1', from_file='./.env', SpaceAndTime_parent=sxt)
    tbl.create_ddl = """
    CREATE TABLE {table_name} 
    ( MyID         int
    , MyName       varchar
    , MyNumber     int
    , Primary Key  (MyID) 
    ) {with_statement} 
    """
    tbl.add_biscuit('admin',sxt.GRANT.ALL)
    if not tbl.exists: 
        tbl.create()
    else:
        tbl.delete(where='1=1')

    data_in = [ {'MyID':1, 'MyName':'Abby',  'MyNumber':6}
            ,{'MyID':2, 'MyName':'Bob',   'MyNumber':6}
            ,{'MyID':3, 'MyName':'Chuck', 'MyNumber':6}
            ,{'MyID':4, 'MyName':'Daria', 'MyNumber':6}
            ]
    tbl.insert.with_list_of_dicts(data_in)
    success, data = tbl.select()
    assert success
    assert [r['MYNUMBER'] for r in data] == [6, 6, 6, 6]
    pass

    tbl.update.with_sqltext('update {table_name} set MyNumber = 7')
    success, data = tbl.select()
    assert success
    assert [r['MYNUMBER'] for r in data] == [7, 7, 7, 7]

    update_data = [{'MyID':r['MYID'], 'MyNumber':r['MYID']} for r in data]
    tbl.update.with_list_of_dicts('MyID',update_data)
    success, data = tbl.select()
    assert success
    assert sorted([r['MYNUMBER'] for r in data]) == [1, 2, 3, 4]

    update_data = [{'MyID':r['MYID'], 'MyNumber':r['MYID']+10} for r in data]
    tbl.update.with_list_of_dicts('MyID', update_data)
    success, data = tbl.select()
    assert success
    assert sorted([r['MYNUMBER'] for r in data]) == [11, 12, 13, 14]


    # error states:
    update_data = [{'MyNumber':r['MYID']+20} for r in data] # no PK
    success, result = tbl.update.with_list_of_dicts('MyID', update_data)
    assert not success 
    assert result['rows'] == 4
    assert result['errors'] == 4
    assert result['successes'] == 0

    update_data = [{'MyID':r['MYID']} for r in data] # only PK
    success, result = tbl.update.with_list_of_dicts('MyID', update_data)
    assert not success 
    assert result['rows'] == 4
    assert result['errors'] == 4
    assert result['successes'] == 0

    update_data = [{'MyID':r['MYID'], 'MyNumber':r['MYID']*11} for r in data] # missing record
    update_data.append({'MyID':5, 'MyNumber':55})
    success, result = tbl.update.with_list_of_dicts('MyID', update_data)
    assert not success 
    assert result['rows'] == 5
    assert result['errors'] == 1
    assert result['successes'] == 4

    update_data = [{'MyID':r['MYID'], 'MyNumber':r['MYID']*11} for r in data] # missing record
    update_data.append({'MyID':5, 'MyNumber':55})
    success, result = tbl.update.with_list_of_dicts('MyID', update_data, upsert = True)
    assert success 
    assert result['rows'] == 5
    assert result['errors'] == 0
    assert result['successes'] == 5

    success, results = tbl.delete(where = 'MyID in(1,3,5)')
    assert success
    assert results == [{'UPDATED': 3}]

    success, results = tbl.delete(where = 'MyID = 12345')
    assert success
    assert results == [{'UPDATED': 0}]

    if tbl.exists:  
        success, result = tbl.drop()
        assert success

    pass

if __name__ == '__main__':
    test_inserts_deletes_updates()
    pass 