import setup, teardown

from pathlib import Path 
from random import randint
from pprint import pprint

from spaceandtime import SpaceAndTime, SXTTable, SXTView


# conventions for ease of testing...
randnum = str(randint(0,999999)).rjust(6,'0')
thisfile = Path(__file__)


# connect to the network and authenticate (with local .env file)
sxt = SpaceAndTime( application_name = thisfile.stem , default_local_folder = thisfile.parent )
sxt.authenticate()


# create a test table:
myTable = SXTTable(f'TEMP.MyTable_{randnum}', access_type=sxt.TABLE_ACCESS.PERMISSIONED, 
                   new_keypair=True, SpaceAndTime_parent=sxt)
myTable.create_ddl = """
       CREATE TABLE {table_name} 
        ( MyID         int
        , MyName       varchar
        , MyDate       date
        , Primary Key  (MyID) 
        ) {with_statement} 
        """

# create biscuits
myTable.add_biscuit('Admin', sxt.GRANT.ALL)
myTable.add_biscuit('Read', sxt.GRANT.SELECT)
myTable.add_biscuit('Load', sxt.GRANT.SELECT, sxt.GRANT.INSERT, sxt.GRANT.DELETE, sxt.GRANT.UPDATE)

# create table
myTable.save()
success, results = myTable.create()

if success:  
    
    # insert some data:
    myData = [ {'MyID':i, 'MyName':chr(64+i), 'MyDate':f'2023-09-0{i}' } for i in list(range(1,11))]
    success, results = myTable.insert.with_list_of_dicts(myData)

    # quick select data from DB (use sxt.execute_query() for full SQL)
    success, data = myTable.select()
    pprint(data)

    # delete half the records    
    myTable.delete(where='MyID > 5')

    # quick select data from DB
    pprint( myTable.select() )


    # create a view (with same key as table)
    myView = SXTView(f'TEMP.myView_{randnum}', private_key=myTable.private_key, SpaceAndTime_parent=sxt)
    myView.create_ddl = f"""
        CREATE VIEW {myView.view_name} 
        {myView.with_statement} 
        AS
        SELECT * FROM {myTable.table_name} 
        WHERE MyID in(2,4,6,8) """ 
    myView.add_biscuit('Admin', sxt.GRANT.ALL)
    myView.table_biscuit = myTable.get_biscuit('Read') # required to prove authorization

    myView.save()
    success, results = myView.create()

    if success: pprint( myView.select() )

    input('Last chance to use Debug Console to play around, beforw we start dropping objects for clean-up...')


    view_drop_success,  view_drop_results  = myView.drop()
    table_drop_success, table_drop_results = myTable.drop()
    
# if we've dropped both view and table, we can clean up files (if desired)
if view_drop_success and table_drop_success:
    Path(myView.recommended_filename).unlink(True)
    Path(myTable.recommended_filename).unlink(True)






# What if you want to raise error on any failure, instead of testing for Success?
errTable = SXTTable(f'TEMP.errTable_{randnum}', access_type=sxt.TABLE_ACCESS.PERMISSIONED, 
                   new_keypair=True, SpaceAndTime_parent=sxt)
errTable.create_ddl = """
       CREATE TABLE {table_name} 
        ( MyID         Bad_DataType -- This will error
        , MyName       varchar
        , Primary Key  (MyID) 
        ) {with_statement} 
        """
errTable.add_biscuit('Admin', sxt.GRANT.ALL)
success, results = errTable.create()

if not success: errTable.raise_error()
