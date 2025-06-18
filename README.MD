
  
  

## Python Space and Time SDK 

  

Python SDK for Space and Time Gateway (python version >= 3.11)

  

## Installation Instructions

  

_Note: The recommended approach to storing keys is using an `.env` file. 
For more information, please see: https://docs.spaceandtime.io/docs/dotenv_

  

```sh
pip install spaceandtime
```

 
  

### Getting Started

```python
# Initializing the Space and Time usage.
from spaceandtime import SpaceAndTime

sxt = SpaceAndTime()
sxt.authenticate()

success, rows = sxt.execute_query(
	'select * from POLYGON.BLOCKS limit 5')
print( rows )
```

The authentication without arguments will seek out a default `.env` file and use credentials found there.  It also supports passing in a specific ```filepath.env``` or simply supplying ```user_id``` and ```private_key```.

The generated ``access_token`` is valid for 25 minutes and the ``refresh_token`` for 30 minutes.

There are a number of convenience features in the SDK for handling return data sets. By default, data sets are returned as a list-of-dictionaries, however can be easily turned into other formats, such as CSV.

```python
# use triple-quotes to insert more complicated sql:
success, rows = sxt.execute_query("""
	SELECT 
	substr(time_stamp,1,7) AS YrMth
	,count(*) AS block_count
	FROM polygon.blocks 
	GROUP BY YrMth
	ORDER BY 1 desc """ )

# print results as CSV
print( sxt.json_to_csv(rows) )
```

More data transforms will be added over time.

### SXTUser Object

All SQL requests are handled by an authenticated user object.  The ```sxt``` wrapper object contains a 'default user' object for simplicity, managing and authenticating as needed.  It is however exposed if needed:

```python
print( sxt.user )
```

You can also manage users directly.  This allows you to load and authenticate multiple users at a time, in case your application needs to manage several accounts.

_**All interaction with the network requires an authenticated user.**_

The user object owns the authenticated connection to the network, so all requests are submitted by a user object.

```python
# Multiple Users
from spaceandtime import SXTUser

suzy = SXTUser('./users/suzy.env', authenticate=True)

bill = SXTUser()
bill.load()         # defaults to "./.env"
bill.authenticate()

# new user
pat = SXTUser(user_id='pat')
pat.new_keypair()
pat.api_url = suzy.api_url
pat.save() # <-- Important! don't lose keys!
pat.authenticate()
```

There is also some capability to administer your subscription using the SDK.  This capability will expand more over time.

```python
# suzy invites pat to her subcription:
if suzy.user_type in ['owner','admin']: 
	joincode = suzy.generate_joincode()
	success, results = pat.join_subscription(joincode)
	print( results )
```



### DISCOVERY

There are several discovery functions that allow insight to the Space and Time network metadata.


```python
# discovery calls provide network information
success, schemas = sxt.discovery_get_schemas()

print(f'There are {len(schemas)} schemas currently on the network.')
print(schemas)
```


### Creating Tables

The SDK abstracts away complexity from making a new table into a Table object.  This object contains all needed components to be self-sufficient _EXCEPT_ for an authenticated user object, which is required to submit the table creation to the network.

```python
# Create a table
from spaceandtime import SXTTable, SXTTableAccessType

tableA = SXTTable(name = "SXTTEMP.MyTestTable", 
				new_keypair = True, 
				default_user = sxt.user,
				logger = sxt.logger,
				access_type = SXTTableAccessType.PERMISSIONED)

tableA.create_ddl = """
	CREATE TABLE {table_name} 
	( MyID         int
	, MyName       varchar
	, MyDate       date
	, Primary Key(MyID) 
	) {with_statement}
""" 

# create new biscuits for your table
tableA.add_biscuit('read',  tableA.PERMISSION.SELECT )

tableA.add_biscuit('write', tableA.PERMISSION.SELECT, 
							tableA.PERMISSION.INSERT, 
							tableA.PERMISSION.UPDATE, 
							tableA.PERMISSION.DELETE,
							tableA.PERMISSION.MERGE )

tableA.add_biscuit('admin', tableA.PERMISSION.ALL )

tableA.save() # <-- Important!  Don't lose your keys!

# create with assigned default user
success, results = tableA.create()  
```


The ```table.create_ddl``` and ```table.with_statement``` property will substitute {names} to replace with class values.  In the example above, the ```{table_name}``` will be replace with ```tableA.table_name``` and the ```{with_statement}``` will be replaced with a valid WITH statement, itself with substitutions for ```{public_key}``` and ```{access_type}```.

Note, if the ```{with_statement}``` placeholder is absent, the table object will attempt to add dynamically.

When adding biscuits, they can either be added as string tokens, or as SXTBiscuit type objects, or as a list of either.

The ```tableA.save()``` function will save all keys, biscuits, and table attributes to a shell-friendly format, such that you could execute the file in shell and load all values to environment variables, for use in other scripting. For example,

```sh
Stephen~$ . ./table--SXTTEMP.New_TableName.sql
Stephen~$ echo $TABLE_NAME
  SXTTEMP.New_TableName
```
This allows table files created in the python SDK to be used with the SxT CLI. 


### Insert, Deletes, and Selects

There are helper functions to assist quickly adding, removing, and selecting data in the table.  Note, these are just helper functions for the specific table object - for more general SQL interface, use the ```sxt.execute_query()``` function. 

```python
from pprint import pprint # for better viewing of data

# generate some dummy data
data = [{'MyID':i, 'MyName':chr(64+i), 'MyDate':f'2023-09-0{i}'} for i in list(range(1,10))]

# insert into the table
tableA.insert.with_list_of_dicts(data)

# select out again, just for fun
success, rows = tableA.select()
pprint( rows )

tableA.delete(where='MyID=6')

# one less than last time
success, rows = tableA.select()
pprint( rows )
```

### Creating Views 

The SXTView object inherits from the same base class as SXTTable, so the two are very similar.  One notable difference is a view's need for a biscuit for each table referenced.  To add clarity and remind of this requirement, a view contains a ```table_biscuit``` property. Also note that views don't need DML PERMISSIONS, like insert or delete.

```python
# create a view 
from spaceandtime import SXTView

viewB = SXTView('SXTTEMP.MyTest_Odds',
 				default_user=tableA.user, 
				private_key=tableA.private_key, 
				logger=tableA.logger)

viewB.add_biscuit('read', viewB.PERMISSION.SELECT)
viewB.add_biscuit('admin', viewB.PERMISSION.ALL) 
viewB.table_biscuit = tableA.get_biscuit('admin')

viewB.create_ddl = """
	CREATE VIEW {view_name} 
	{with_statement} 
	AS
	SELECT *
	FROM """ + tableA.table_name + """
	WHERE MyID in (1,3,5,7,9) """

viewB.save() # <-- Important! don't lose keys!

success, results = viewB.create()
```

We've used the same private key for the table and the view.  This is NOT required, but is convenient if you are building a view atop only one table.  

Each object comes with a pre-built ```recommended_filename``` which acts as the default for ```save()``` and ```load()```.  

```python
print( tableA.recommended_filename )
print( viewB.recommended_filename )
print( suzy.recommended_filename )
```

Once you're done, it's best practice to clean up.  

```python
viewB.drop()
tableA.drop()
```
