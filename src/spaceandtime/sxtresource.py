import logging, json, math, time, os
from pysteve import pySteve
from pathlib import Path
from datetime import datetime
from .sxtenums import SXTResourceType, SXTPermission, SXTKeyEncodings, SXTTableAccessType
from .sxtexceptions import SxTArgumentError, SxTFileContentError, SxTExceptions
from .sxtbiscuits import SXTBiscuit
from .sxtkeymanager import SXTKeyManager
from .sxtuser import SXTUser

class SXTResource():
    # child objects should override: self.__with__, has_with_statement(), self.resource_type

    logger: logging.Logger
    SXTExceptions = None
    resource_type:SXTResourceType = SXTResourceType.UNDEFINED
    PERMISSION = SXTPermission
    create_ddl:str = ''
    user: SXTUser = None
    key_manager: SXTKeyManager = None
    filepath: Path = ''
    application_name:str = ''
    biscuits = []
    start_time: datetime = None
    __rcn:str = ''
    __ddlt__:str = ''
    __allprops__: list = []
    __with__:dict 
    __existfunc__ = None
    default_local_folder:Path = None
    __foname__:str = 'resources'
    __lasterr__ = None


    def __init__(self, name:str=None, from_file:Path=None, default_user:SXTUser = None, 
                 private_key:str = None, new_keypair:bool = False, key_manager:SXTKeyManager = None,
                 application_name:str = None, start_time:datetime = None, 
                 default_local_folder:Path = None,
                 logger:logging.Logger = None, SpaceAndTime_parent:object = None) -> None:
        
        # start with parent
        if SpaceAndTime_parent:
            if not application_name: application_name = SpaceAndTime_parent.application_name
            if not logger: logger = SpaceAndTime_parent.logger
            if not default_user: default_user = SpaceAndTime_parent.user
            # if not key_manager: key_manager = SpaceAndTime_parent.key_manager  # this gets confused with Default.User, so removing
            if not default_local_folder: default_local_folder = SpaceAndTime_parent.default_local_folder
            if not start_time: start_time = SpaceAndTime_parent.start_time

        # set logger if set, otherwise create new
        if logger: 
            self.logger = logger 
        else: 
            self.logger = logging.getLogger()
            self.logger.setLevel(logging.INFO)
            if len(self.logger.handlers) == 0: 
                self.logger.addHandler( logging.StreamHandler() )

        # load parameters from file into variables 
        if not default_local_folder: default_local_folder = '.'
        self.default_local_folder = Path(Path(default_local_folder) / Path( self.__foname__ )) 
        self.biscuits = []    
        if from_file: self.load(from_file)

        # Continue setting parameters if they exist, or if not, supply new objects /defaults
        # overriding anything set above
        if name: self.resource_name = name
        self.user = default_user if default_user else SXTUser()
        self.application_name = application_name 
        self.start_time = start_time if start_time else datetime.now()  
        if key_manager and type(key_manager)==SXTKeyManager:
            self.key_manager = key_manager
            if private_key: self.key_manager.private_key = private_key
        elif self.key_manager == None:
            self.key_manager = SXTKeyManager(private_key=private_key, new_keypair=new_keypair, logger=logger, encoding=SXTKeyEncodings.BASE64 )

        # add exceptions, for visibility
        self.SXTExceptions = SxTExceptions

        # generate list of properties to expose to user during find/replace or logging
        self.__with__ = {"public_key":"{public_key}"}
        self.__allprops__ = [self.resource_type.value, 'start_time','resource_name','resource_type','resource_name_template',
                             'resource_private_key','resource_public_key','biscuits',
                             'with_statement', 'create_ddl_template','create_ddl']
        
        # set function to call to evaluate whether this resource exists
        self.__existfunc__ = self.user.base_api.discovery_get_tables
        

    def __str__(self) -> str:
        line_formatter = lambda n,v: f"{str(n).rjust(20)} = {v}"
        biscuit_formatter = lambda n,v: f"\n{str(n)}: \n{v}"
        sql_formatter = lambda n,v: f"{'- '*30}\n{str(n)}: \n{v}\n"
        lines = list(self.to_list(True, 
                                  func_line_formatter=line_formatter, 
                                  func_biscuit_formatter=biscuit_formatter, 
                                  func_sql_formatter=sql_formatter))
        lines.insert(0,f"\n {'-'*11}{'='*10} {self.resource_name} {'='*10}{'-'*11}" )
        return '\n'.join(lines)

    def __repr__(self) -> str:
        line_formatter = lambda n,v: f"{str(n).rjust(20)} = {v}"
        biscuit_formatter = lambda n,v: f"{str(n)}: \n{v}\n"
        sql_formatter = lambda n,v: f"{'- '*30}\n{str(n)}: \n{v}\n"
        lines = list(self.to_list(False, 
                                  func_line_formatter=line_formatter, 
                                  func_biscuit_formatter=biscuit_formatter, 
                                  func_sql_formatter=sql_formatter))
        lines.insert(0,f"\n {'-'*10}{'='*10} {self.resource_name} {'='*10}{'-'*10}" )
        return '\n'.join(lines)


    @property
    def private_key(self) ->str :
        return self.key_manager.private_key
    @private_key.setter
    def private_key(self, value):
        self.key_manager.private_key = value 
        self.__bt = ''

    @property
    def public_key(self) ->str :
        return self.key_manager.public_key
    @public_key.setter
    def public_key(self, value):
        self.key_manager.public_key = value 

    @property
    def encoding(self) ->str :
        return self.key_manager.encoding
    @encoding.setter
    def encoding(self, value):
        self.key_manager.encoding = value     

    @property
    def resource_name_template(self) -> str:
        return self.__rcn
    @resource_name_template.setter
    def resource_name_template(self, value):
        self.__rcn = value 

    @property
    def resource_name(self) -> str:
        tmpprops = [k for k in self.__allprops__ if k not in ['resource_name','biscuits','create_ddl',self.resource_type.value, 'with','with_statement']]
        return self.replace_all(self.__rcn, self.to_dict(False, tmpprops) )
    @resource_name.setter
    def resource_name(self, value):
        if self.__rcn !='' and self.__rcn.lower() != value.lower():
            for biscuit in self.biscuits: # update "capabilities" to new name
                if not biscuit._SXTBiscuit__manualtoken:
                    biscuit._SXTBiscuit__cap[value] = biscuit._SXTBiscuit__cap[self.__rcn]
                    del biscuit._SXTBiscuit__cap[self.__rcn]
                    biscuit.regenerate_biscuit_token()
        self.__rcn = value 
        

    @property
    def recommended_filename(self) -> Path:
        filename = f'{str(self.resource_type.name).lower()}--{self.resource_name}' 
        filename = f"{filename}--v{self.start_time.strftime('%Y%m%d%H%M%S')}.sql"
        return Path( self.default_local_folder / Path(filename)).resolve()

    @property
    def create_ddl(self) -> str:
        tmpprops = [k for k in self.__allprops__ if k not in ['biscuits','create_ddl']]
        ddl = self.replace_all( mainstr= self.create_ddl_template, replace_map = self.to_dict(False, tmpprops) ).rstrip()
        if self.has_with_statement(ddl): return ddl 
        if ddl[-1:] == ';': ddl = ddl[:-1]
        return f'{ddl} \n{self.with_statement}'
    @create_ddl.setter
    def create_ddl(self, value):
        self.__ddlt__ = str(value)
    
    @property
    def create_ddl_template(self) -> str:
        return str(self.__ddlt__)
    @create_ddl_template.setter
    def create_ddl_template(self, value):
        self.__ddlt__ = str(value)
        
    @property
    def with_statement(self) -> str:
        tmpprops = [k for k in self.__allprops__ if k not in ['biscuits','create_ddl','create_ddl_template','with','with_statement']]
        tmpencoding = self.key_manager.encoding
        if tmpencoding != SXTKeyEncodings.HEX: self.key_manager.encoding = SXTKeyEncodings.HEX
        tmpwith =  'WITH "' + ','.join([ f"{n}={v}" for n,v in self.__with__.items() ]) + '"'
        rtn = self.replace_all(tmpwith, self.to_dict(False, tmpprops) )
        if tmpencoding != SXTKeyEncodings.HEX: self.key_manager.encoding = tmpencoding
        return rtn 
    
    @property
    def create_ddl_sample(self) -> str:
        """Returns a simple, sample CREATE TABLE template string."""
        return """
        CREATE TABLE {table_name} 
        ( MyID         int
        , MyName       varchar
        , MyDate       date
        , Primary Key  (MyID) 
        ) {with_statement} """


    @property
    def exists(self) -> bool:
        """Returns True of the resource appears on the Space and Time network, or False if it is missing.  
        Returns None if a connection cannot be established or encountered an error."""
        if self.user.access_expired: self.user.authenticate()
        # __existfunc__ is defined by the interhiriting child class (table, view, etc.) which has the same signature, but called here
        success, resources = self.__existfunc__(schema=self.schema)
        if success:
            apiname = 'table' if self.resource_type.name.lower() == 'table' else 'view'

            does_exist = str(self.name).upper() in [ r[apiname] for r in resources]
            self.logger.debug(f'testing whether {self.resource_name} exists:  {str(does_exist)}')
            return does_exist 
        else:
            self.logger.warning(f'There was a problem deteriming whether resource exists: {self.resource_name} (returning None)\n{resources}')
            return None


    @property
    def schema(self) -> str:
        """Returns the schema portion of the Resource_Name (read only)."""
        return self.resource_name.split('.')[0]
        
    @property
    def name(self) -> str:
        """Returns the Resource_Name, without the schema (read only)."""
        return self.resource_name.split('.')[1]
        

    def new_keypair(self) -> dict:
        """--------------------
        Generate a new ED25519 keypair, set class variables and return dictionary of values.

        Returns: 
            dict: New keypair values
         """
        return self.key_manager.new_keypair()


    def add_biscuit_object(self, *biscuit_objects:SXTBiscuit) -> SXTBiscuit:
        """Adds one-or-more SXTBiscuit objects to the resource.
        
        Args:
            bsicuit_objects (SXTBiscuit): Biscuit objects to add to resource

        Returns:
            list: objects added 
        """
        for biscuit_object in biscuit_objects:
            self.biscuits.append(biscuit_object)
        return biscuit_objects


    def add_biscuit(self, name:str = '', *permissions) -> SXTBiscuit:
        """--------------------
        Creates a new SXTBiscuit and adds to the resource.

        Args: 
            name (str): Name for the biscuit.  Used to search/recall the specific object if needed.
            *permissions: One-or-more permissions to grant with the biscuit, using SXTPermissions enum.

        Returns:
            SXTBiscuit: biscuit that was created and added.

        Examples:
            >>> myTable = SXTTable('schema.myTable')
            >>> myTable.add_biscuit('Admin', SXTPermission.ALL)
            >>> myTable.add_biscuit('Load', SXTPermission.INSERT, SXTPermission.SELECT)
            >>> myTable.add_biscuit('Read', SXTPermission.SELECT)
        """
        if not self.private_key:
            raise SxTArgumentError('Resource requires a private key to be set before making new biscuits.', logger=self.logger)
        biscuit = SXTBiscuit(name=name, private_key=self.private_key, logger=self.logger )
        biscuit.add_capability(self.resource_name, *permissions)
        self.biscuits.append(biscuit)
        return biscuit
    

    def get_biscuit(self, by_name:str) -> list:
        """Returns a SXTBiscuit object by name."""
        return  [b for b in self.biscuits if b.name == by_name]

            
    def clear_biscuits(self):
        """Clears all biscuits from the Resource.  Note, this does not invalidate existing in-use biscuits, 
        simply clears the biscuit list from the local resource."""
        self.biscuits = []        


    def replace_all(self, mainstr:str, replace_map:dict = None) -> str:
        """Within mainstr, replaces all instances of {replace_map.key} from replace_map with  replace_map.value."""
        if not replace_map: replace_map = {}
        if 'date' not in replace_map.keys(): replace_map['date'] = int(self.start_time.strftime('%Y%m%d'))
        if 'time' not in replace_map.keys(): replace_map['time'] = int(self.start_time.strftime('%H%M%S'))
        if 'resource_public_key'  in replace_map.keys(): replace_map['public_key']  = replace_map['resource_public_key']
        if 'resource_private_key' in replace_map.keys(): replace_map['private_key'] = replace_map['resource_private_key']
        # if 'with_statement' in replace_map.keys(): replace_map['with'] = replace_map['with_statement']
        for findname, replaceval in replace_map.items():
            mainstr = str(mainstr).replace('{'+str(findname)+'}', str(replaceval))                    
        return mainstr


    def to_json(self, obscure_private_key:bool = True, omit_keys:list = []) -> json:
        """--------------------
        Returns a json document containing relevant information from the Resource object.

        Args:
            obscure_private_key (bool): If True will only display first 6 characters of private keys.
            omit_keys (list): List of key names to exclude from the return. 
            
        Returns:
            json: JSON representation of the class.
        """
        return json.dumps(self.to_dict(obscure_private_key=obscure_private_key, omit_keys=omit_keys))
    

    def to_dict(self, obscure_private_key:bool = True, include_keys:list = []) -> dict:
        """--------------------
        Returns a dictionary object containing relevant information from the Resource object.

        Args:
            obscure_private_key (bool): If True will only display first 6 characters of private keys.
            include_keys (list): List of key names to include in the return.  Defaults to all keys.
            
        Returns:
            dict: Curated dictionary of relevant values in the class.
        """
        if include_keys ==[]: include_keys = self.__allprops__
        rtn = {}
        for prop in include_keys:
            match prop:
                case 'resource_type':  rtn[prop] = self.resource_type.name
                case self.resource_type.value: rtn[prop] = self.resource_name
                case 'resource_private_key': rtn[prop] = self.private_key[:6]+'...' if obscure_private_key else self.private_key
                case 'resource_public_key': rtn[prop] = self.public_key
                case 'with_statement': 
                    rtn[prop] = self.with_statement
                    rtn['with'] = self.with_statement
                case 'start_time': 
                    rtn[prop] = self.start_time.strftime('%Y-%m-%d %H:%M:%S')
                    rtn['date'] = int(self.start_time.strftime('%Y%m%d'))
                    rtn['time'] = int(self.start_time.strftime('%H%M%S'))
                case 'biscuits': 
                    rtn[prop] = {}
                    for bis in self.biscuits:
                        if bis and type(bis) == SXTBiscuit:
                            rtn[prop][bis.name] = bis.biscuit_token
                case _:
                    rtn[prop] = getattr(self, prop, str('')) 
                    if type(rtn[prop]) == SXTTableAccessType: rtn[prop] = rtn[prop].value
        return  rtn
    

    def to_list(self, obscure_private_key:bool = True, 
                include_keys:list = [],
                func_line_formatter = lambda n,v: f'{n}={v}', 
                func_biscuit_formatter = lambda n,v: f'{n}_biscuit_token={v}',
                func_sql_formatter = lambda n,v: f'{n}\n:{v}') -> list:
        """------------------
        Returns a list object containing relevant information from the Resource object, with name/value formatted to one line.

        Args:
            obscure_private_key (bool): If True will only display first 6 characters of private keys
            omit_keys (list): List of key names to exclude from the return
            func_line_formatter (function): Function that accepts two parameters (name, value) and returns a single string. Defaults to lambda n,v: f'{n}={v}' 
            func_biscuit_formatter (function): Same as line_formatter, but used specifically for any biscuit nested objects found
            func_sql_formatter (function): Same as line_formatter, but used specifically for any names containing 'ddl' or 'sql'
            
        Returns:
            list: List representation of the class.
        """
        rtn = []
        for n,v in self.to_dict(obscure_private_key=obscure_private_key, include_keys=include_keys).items():
            if n=='biscuits':
                for bname, token in dict(v).items():
                    rtn.append(func_biscuit_formatter(bname, token))
            elif 'ddl' in n or 'sql' in n:
                rtn.append(func_sql_formatter(n,v))
            else:
                rtn.append(func_line_formatter(n,v))
        return rtn


    def get_first_valid_user(self, *users) -> SXTUser:
        """
        Returns the first valid SXTUser object passed into the arguments list, or 
        current object default user, if available.
        """
        all_user_objects = [user for user in (list(users) + [self.user]) if type(user) == SXTUser]
        if all_user_objects == []:
            self.logger.warning('No SXTUser objects were provided. Returning None, but this may cause downstream errors.')
            return None
        
        all_valid_user_objects = [user for user in all_user_objects if len(user.user_id)>0 and len(user.private_key)>0]
        if all_valid_user_objects == []:
            self.logger.warning('None of the supplied SXTUser objects appear capable of connecting to SXT Network. Returning the first, but this may cause downstream errors.')
            return all_user_objects[0]

        return all_valid_user_objects[0]
     

    def create(self, sql_text:str = None, user:SXTUser = None, biscuits:list = None):
        """--------------------
        Issues the supplied (parameterized) CREATE statement to the Space and Time network, and report back success and details.

        Args:
            sql_text (str): Parameterized CREATE statement.  If omitted, will use the resource.create_ddl class property.  Both will replace {placeholders} with real values before submission.
            user (SXTUser): Authenticated user who will issue the command.  If omitted, will use the default user, resource.user
            biscuits (list): List of biscuits to include with the request, either as string biscuit tokens or as SXTBiscuit objects.  If omitted, will use the class.biscuits list.  Must contain CREATE permissions. 

        Returns: 
            bool: Success flag, True if the object was created.
            object: other details supplied during the request, including API messaging. Typically a dict.
        """
        user = self.get_first_valid_user(user)
        if not sql_text: 
            if self.create_ddl_template == '':
                raise SxTArgumentError('Must set the create_ddl before trying to create the table.', logger=self.logger)
            sql_text = self.create_ddl
        if self.private_key == '': 
            raise SxTArgumentError('Must create or set a keypair before trying to create the table.  Try running new_keypair().', logger=self.logger)
        if not biscuits: biscuits = self.biscuits if type(self.biscuits)==list else [self.biscuits]
        if biscuits == []: 
            self.logger.warning('No biscuits found. While this may be OK, it can also cause errors.')
        success, results = user.base_api.sql_ddl(sql_text=sql_text.strip(), biscuits=biscuits, app_name=self.application_name)
        if success: 
            self.logger.info(f'{self.resource_type.name} Created: {self.resource_name}:\n{sql_text}')
        else:
            self.logger.error(f'{self.resource_type.name} FAILED TO CREATE with user {user.user_id}:\n{results}\n{sql_text}\n\nBiscuits: {biscuits}')
        self.__lasterr__ = None if success else self.SXTExceptions.SxTQueryError(results) 
        return success, results


    def drop(self, user:SXTUser = None, biscuits:list = None):
        """--------------------
        Issues the supplied (parameterized) DROP statement to the Space and Time network, and report back success and details.

        Args:
            user (SXTUser): Authenticated user who will issue the command.  If omitted, will use the default user, resource.user
            biscuits (list): List of biscuits to include with the request, either as string biscuit tokens or as SXTBiscuit objects.  If omitted, will use the class.biscuits list.  Must contain DROP permissions. 

        Returns: 
            bool: Success flag, True if the object was dropped.
            object: other details supplied during the request, including API messaging. Typically a dict.
        """
        self.logger.info(f'{"-"*15}\nDROPPING {self.resource_type.name}: {self.resource_name}...')
        user = self.get_first_valid_user(user)
        if not biscuits: biscuits = list(self.biscuits) 
        if biscuits == []: 
            raise SxTArgumentError('A biscuit with DROP must be included.', logger=self.logger)
        objtype = 'TABLE' if self.resource_type.name.lower()=='table' else 'VIEW'
        sql_text = f'DROP {objtype} {self.resource_name}' 
        success, results = user.base_api.sql_ddl(sql_text=sql_text, biscuits=biscuits, app_name=self.application_name)
        if success: 
            self.logger.info(f'       DROPPED: {self.resource_name}')
        else:
            self.logger.error(f'{self.resource_type.name} FAILED TO DROP with user {user.user_id}:\n{results}\n{sql_text}')
        self.__lasterr__ = None if success else self.SXTExceptions.SxTQueryError(results) 
        return success, results
        

    def select(self, sql_text:str = '', columns:list = ['*'], user:SXTUser = None, biscuits:list = None, row_limit:int = 50) -> tuple[bool, dict]:
        """--------------------
        Issues a SELECT statement to the Space and Time network, and report back success and rows (or failure details).

        This is intended as a convenience feature, to quickly verify data structures or recently loaded data.  While it can 
        run more sophisticated SQL, it is recommended to use the SXTUser object for more flexibility.

        Args:
            sql_text (str): Sql text to execute.  If omitted, will defaults to "SELECT [columns] FROM [resource_name] LIMIT [row_limit]".
            columns (list): List of columns to build the SELECT statement.  Defaults to "*".  If sql_text is supplied, this is ignored.
            user (SXTUser): Authenticated user who will issue the command.  If omitted, will use the default user, resource.user
            biscuits (list): List of biscuits to include with the request, either as string biscuit tokens or as SXTBiscuit objects.  If omitted, will use the class.biscuits list.  
            row_limit (int): Limits the number of rows returned. If set to -1 or None, no row limit is applied. Default 50.

        Returns: 
            bool: Success flag, True if the object was dropped.
            object: Row output of the SQL request, in JSON format, or if error, details returned from the request.

        Examples: 
            >>> suzy = SXTUser('.env', authenticate=True)
            >>> ethblocks = SXTTable(name='ETHEREUM.Blocks', default_user=suzy)
            >>> success, rows = ethblocks.select (columns = 'BLOCK_NUMBER', row_limit = 10)
            >>> len( rows )
            10
            >>> len(rows[0].keys())
            11
        """
        self.logger.info(f'{"-"*15}\nSELECTing {self.resource_type.name} {self.resource_name}...')
        user = self.get_first_valid_user(user)
        if not biscuits: biscuits = list(self.biscuits) 
        if biscuits == []: 
            self.logger.warning('No biscuits found. While this may be OK, it can also cause errors.')
        row_limit = '' if row_limit < 0 or not row_limit else f'LIMIT {row_limit}'
        if sql_text == '': sql_text = f"SELECT { ','.join( columns ) } FROM {self.resource_name} {row_limit}"
        self.logger.info(f'{self.resource_type.name} Query Started: {self.resource_name}:\n{sql_text}')
        success, results = user.base_api.sql_dql(sql_text=sql_text, biscuits=biscuits, resources=self.resource_name, app_name=self.application_name)
        if success: 
            self.logger.info(f'{self.resource_type.name} {self.resource_name} Finished: {len(results)} Rows Returned')
        else:
            self.logger.error(f'{self.resource_type.name} QUERY FAILED with user {user.user_id}:\n{results}\n{sql_text}')
        self.__lasterr__ = None if success else self.SXTExceptions.SxTQueryError(results) 
        return success, results

    
    def clear_all(self) -> None:
        """Clears all content from the object. It is HIGHLY RECOMMENDED you save() before a clear_all(), to prevent key loss. No arguments and None returned."""
        self.clear_biscuits()
        props = [p for p in self.__allprops__ if p not in ['resource_type','with_statement']]
        for prop in props:
            setattr(self, prop, '')
        self.start_time = datetime.now()
        self.key_manager = SXTKeyManager(logger=self.logger, encoding=SXTKeyEncodings.BASE64)
        # TODO: add a 'dirty' flag, and warn if not saved
        self.logger.info(f'{self.resource_type.name} resource has been cleared.')
        return None 
        

    def __filestarts__(self, folderfilepath:Path) -> Path:
        if Path(folderfilepath).exists(): return Path(folderfilepath)
        folderfilepath = Path(folderfilepath).resolve()
        files = sorted([str(file) for file in list(Path(folderfilepath.parent).iterdir()) if str(Path(file).name).startswith(folderfilepath.name)])
        return Path(files[-1:][0]) if len(files) > 0 else None         


    def raise_error(self):
        """If the last database command failed, raise an exception."""
        if self.__lasterr__ == None: return None 
        raise self.__lasterr__
    

    def load(self, filepath:Path, exact_match_only:bool = True, docstring_marker_override:str = None):
        """--------------------
        Loads Resource file *WITH PRIVATE KEYS* to the current object, overwriting all current values.

        The load is expecting a plain-text file in a shell-loadable format, meaning you can run the input file in a 
        terminal /shell, and it will load into environment variables.  This is the same file that the save() function
        produces.  Any NAME=Value format is translated into object variables, including heredocs using the EOM marker.
        For examples, look at the save() file produced.  To prevent losing keys, it is recommended you always
        save() before you load().
        
        Args:
            filepath (Path): File to load into object.
            exact_match_only (bool): If False, will accept incomplete filenames or filenames with iterators.

        Returns: 
            bool: True if load was successful, False if not. 
        """
        if not filepath: raise ValueError(f'Must supply a filepath to load().')
        self.clear_all()        
        
        # just in case, try to catch other past docstring markers
        for trymarkers in [docstring_marker_override, 'EOM', 'EOMsg', None, docstring_marker_override]:
            loadmap = pySteve.envfile_load(load_path=Path(filepath).resolve(), exact_match_only=exact_match_only, docstring_marker_override=trymarkers)
            missed_docstrmarkers = [v for n,v in loadmap.items() if str(v).strip().startswith('$(cat <<') and len(v)<=32]
            if missed_docstrmarkers==[]: break 
        loadmap = {k.lower():loadmap[k] for k in sorted(list(loadmap.keys()))} # sorted to prevent create_ddl / _template overwriting)

        try:    
            for name, value in loadmap.items():
                if name in ('resource_type','start_time','date','time'): continue
                elif name == 'resource_private_key':
                    self.key_manager = SXTKeyManager(private_key=value, encoding=SXTKeyEncodings.BASE64, logger=self.logger)
                elif name == 'access_type':
                    if value in [str(n.value)for n in SXTTableAccessType]:
                        value = SXTTableAccessType[value.upper()]
                    elif 'pub' in value and 'read' in value: value = SXTTableAccessType.PUBLIC_READ
                    elif 'pub' in value and 'writ' in value: value = SXTTableAccessType.PUBLIC_WRITE
                    elif 'pub' in value and 'append' in value: value = SXTTableAccessType.PUBLIC_APPEND
                    elif 'priv' in value: value = SXTTableAccessType.PERMISSSIONED
                    else: continue # just skip
                    setattr(self, name, value)
                elif name.endswith( '_biscuit_token') or name.endswith( '_biscuit'):
                    if type(self.biscuits) != list:  self.biscuits = []
                    self.biscuits.append(SXTBiscuit(name=name.replace('_biscuit_token','').replace('_biscuit',''),
                                                    logger=self.logger, 
                                                    private_key=self.private_key,
                                                    biscuit_token= value))
                else:
                    setattr(self, name, value)
            return True
        except Exception as ex:
            err = ex
        raise SxTFileContentError(f'Failed to load file {filepath}: {err}')
                

    def save(self, filepath:Path = None):
        """--------------------
        Saves Resource file *WITH PRIVATE KEYS* to the specified filepath.  Will not overwrite.

        The format saved is a plain-text file in a shell-loadable format, meaning you can run the output file in a 
        terminal /shell, and it will load into environment variables.  This format can also be loaded into the python 
        SDK using the load() command. To prevent lost keys, this process will specifically NOT OVERWRITE files. It is 
        best practice to version files as needed and keep history.
        
        Args:
            filepath (Path): Where to save the file. If filepath is None, it will use the object's recommended_filename.

        Returns: 
            bool: True if save was successful, False if not. 

        """
        filepath = Path(filepath) if filepath else Path(self.recommended_filename)
        line_formatter = lambda n,v: f'{str(n).upper()}="{v}"'
        biscuit_formatter = lambda n,v: f'{str(n).upper()}_BISCUIT_TOKEN="{v}"'
        sql_formatter = lambda n,v: f'{str(n).upper()}=$(cat << EOM\n{v}\nEOM\n)\n'
        lines = list(self.to_list(obscure_private_key=False,
                                  func_line_formatter=line_formatter, 
                                  func_biscuit_formatter=biscuit_formatter, 
                                  func_sql_formatter=sql_formatter,
                                  include_keys=[p for p in self.__allprops__ if p not in ['with','with_statement','create_ddl']]))
        lines.insert(0, f'# -- Resource File for  {self.resource_name}')
        lines.insert(1, f'# -- this file can be executed as a shell script to set environment variables')
        for i, line in enumerate(lines):
            if str(line).startswith('CREATE_DDL'): 
                lines.insert(i, '# -- SQL:')
                break
        for i, line in enumerate(lines):
            if 'BISCUIT_TOKEN' in line:
                lines.insert(i, '# -- BISCUITS:')
                break
        fp = Path(self.replace_all(str(filepath), self.to_dict(False))).resolve()
        self.logger.info(f'Saving Resource File: {fp}')
        if fp.exists():
            self.logger.error(f'File Exists: {fp.resolve()}\nTo minimize lost keys, file over-writes are not allowed.')
            raise FileExistsError('To minimize lost keys, file over-writes are not allowed.')
        else:
            if not fp.parent.exists(): fp.parent.mkdir(parents=True, exist_ok=True)
            try:
                with open(fp.resolve(), 'w') as fh:
                    fh.write( '\n'.join(lines) )
            except Exception as ex:
                self.logger.error(f'Error while saving Resource File: {ex}')
                return False 
        return True


    def has_with_statement(self, create_ddl:str) ->bool:
        """-------------------
        Returns True/False as to whether supplied Create Resource SQL has a WITH statement.
        
        Args:
            create_ddl (str): The Create Resource DDL / SQL to analyze for a WITH statement.

        Returns: 
            bool: True if the WITH statement was found, FALSE if not. 
        """
        create_ddl = create_ddl.replace('{with_statement}','').replace('{with}','')
        if 'with' not in create_ddl.lower(): return False
        r6 = '' # rolling 6 chars
        for i in range(len(create_ddl)-6, 0, -1):
            r6 = create_ddl[i:i+6]
            if r6[1:5].lower() == 'with' and not r6[0:1].isalnum() and not r6[5:6].isalnum(): return True
            if r6[0:1] == ')': return False
        return False


    def safe_column_name(self, original_column_name:str) -> str:
        """--------------------
        Accepts a string and returns a DB column safe string, absent special characters.
        """
        rtn = original_column_name.strip().replace(' ','_').replace('-','_')
        rtn = [c for c in rtn if c.isalnum() or c=='_']
        if rtn[0].isnumeric(): rtn.insert(0,'_')
        rtn = str(''.join(rtn))
        while '__' in rtn:
            rtn = rtn.replace('__','_')
        if rtn.lower() in ['name', 'type', 'parent', 'object', 'select', 'where',
                           'varchar', 'decimal', 'integer', 'int', 'from', 'to']:
            rtn = f'{rtn}_'
        return rtn
    
    def safe_column_value(self, original_column_value:str = '') -> str:
        """--------------------
        Accepts a string and returns a DB safe insert string, wrapped in quotes with escape characters.
        """
        return "'" + str(original_column_value).strip().replace("'","''") + "'"  if original_column_value!=None else 'NULL'
        # if original_column_value==None: original_column_value = 'NULL'
        # rtn = "'" + str(original_column_value).strip().replace("'","''") + "'"
        # return rtn





class SXTTable(SXTResource):
    access_type: SXTTableAccessType 
    __pc__: str = None 

    def __init__(self, name:str='', from_file:Path=None, default_user:SXTUser = None, 
                 private_key:str = '', new_keypair:bool = False, key_manager:SXTKeyManager = None,
                 access_type:SXTTableAccessType = SXTTableAccessType.PERMISSIONED,
                 application_name:str = None, start_time:datetime = None,
                 default_local_folder:Path = None,
                 logger:logging.Logger = None, SpaceAndTime_parent:object = None) -> None:
        """--------------------
        Creates a new Space and Time Table object.

        Accepts a good number of settings during init, either individually (name, private_key,
        access_type) or use from_file to pass in Path to a save() file to reload previous config.
        Similarly, object parameters can be passed in individually (application_name, logger, 
        key_manager, default_user) or pass in the SpaceAndTime_parent object, and those objects
        will be inherited automatically.  The SpaceAndTime parameters are loaded first, 
        overridden by anything in the from_file, overridden by individual parameters.

        Args:
            name (str): Name of Schema.TableName
            from_file (Path): Path location of a saved file to load from.
            default_user (SXTUser): User to use when no other user is specified.
            private_key (str): Private key for the Resource (not user), in Base64, Hex, or Binary.
            new_keypair (bool): If True, creates a new keypairs, overriding key_manager but not private_key (if set).
            key_manager (SXTKeyManager): Key manager object
            access_type (SXTTableAccessType): Access type of table, by enum (permissioned, public_read, etc.)
            application_name (str): Name of the application, for logging and Space And Time query logging (if enabled).
            start_time (datetime): Starting time of the process (for uniformity across objects).
            default_local_folder (Path): default local path for saving / loading files.
            logger (Logger): Python Logger object, with which to log all activity.
            SpaceAndTime_parent (SpaceAndTime): parent SpaceAndTime class object to inherit default_user, key_manager, application_name, and logger.
        """
        self.resource_type = SXTResourceType.TABLE    
        self.__foname__ = 'tables'
        super().__init__(name, from_file, default_user, private_key, new_keypair, key_manager, application_name, start_time, default_local_folder, logger, SpaceAndTime_parent)
        self.access_type = access_type
        self.__allprops__.insert(2, 'access_type')
        self.__with__=  {"public_key":"{public_key}", "access_type":"{access_type}"}
        self.insert = self.__ins__(self)
        self.update = self.__upd__(self)
        self.__existfunc__ = self.user.base_api.discovery_get_tables
        
    @property
    def table_name(self) ->str:
        return self.resource_name
    @table_name.setter
    def table_name(self, value):
        self.resource_name = value
    

    __cols__:dict = None
    @property
    def columns(self) -> dict: 
        if self.__cols__ is None: self.get_column_names()
        return self.__cols__
    @columns.setter
    def columns(self, value): self.__cols__ = value


    @property
    def partition_column(self) -> str:
        if 'partition_cols' in self.__with__.keys:
            return self.__with__['partition_cols']
        else:
            return None 
    @partition_column.setter
    def partition_column(self, value:str):
        if len(value) == 0 and 'partition_cols' in self.__with__.keys:
            self.__with__.pop('partition_cols')
        elif len(value) > 0:
            self.__with__['partition_cols'] = str(value)

    @property
    def immutable(self) -> bool:
        return 'immutable' in self.__with__.keys
    @immutable.setter
    def immutable(self, value:bool):
        if type(value) != bool: raise ValueError("Attribute 'immutable' must be a boolean type.")
        if value: 
            self.__with__['immutable'] = 'true'
        else:
            self.__with__.pop('immutable','') 

    @property
    def require_primary_key(self) -> bool:
        return 'key_type' not in self.__with__.keys
    @require_primary_key.setter
    def require_primary_key(self, value:bool):
        if type(value) != bool: raise ValueError("Attribute 'require_primary_key' must be a boolean type.")
        if value:
            self.__with__.pop('key_type','') 
        else: 
            self.__with__['key_type'] = 'RandomString'
            


    def get_column_names(self) -> dict:
        """Returns a dictonary of column_name : data_type as defined in the create_ddl.
        
        Useful when an iterable list of columns (and types) is required, such as building 
        INSERT statements or view SELECT lists.  Pulled from the discovery API - if table
        does not exist on the network, returns an empty dictionary.
        """
        rtn = {}
        success, rtn = self.user.base_api.discovery_get_columns(self.schema, self.name)
        if success:
            self.__cols__ = {c['column']:c for c in rtn}
            return {c['column']:c['dataType'] for c in rtn}
        else: return {}

        # # prep ddl to isolate columns 
        # ddl = str(self.create_ddl).replace('\t',' ').replace('\n',' ').strip()
        # while '  ' in ddl: ddl = ddl.replace('  ',' ')
        # first_paren = ddl.find('(')+1
        # for i in range(len(ddl), 1, -1):
        #     if ddl[i:i+1] == ')': 
        #         last_paren = i 
        #         break
        # 
        # # process columns
        # cols = [c.strip() for c in ddl[first_paren:last_paren].split(',') ]
        # for col in cols:
        #     if col.lower().startswith('primary key'): continue
        #     colname = col.split(' ')[0]
        #     coltype = col.split(' ')[1]
        #     rtn[colname] = coltype
        #
        # return rtn


    class __ins__():
        def __init__(self, resource:SXTResource) -> None:
            self.__rc__ = resource

        def with_sqltext(self, sql_text:str, biscuits:list = None, user:SXTUser = None, **kwargs) -> tuple[bool, dict]:
            """--------------------
            Submits a single INSERT statement to the Space and Time network.

            Args:
                sql_text (str): INSERT statement to submit to the SxT Network.
                biscuits (list): List of biscuits to authorize the request. Defaults to all biscuits added to the object.
                user (SXTUser): User who will execute the request. Defaults to the default user.

            Returns: 
                bool: Success flag, True if the data was fully inserted, False if any of the records failed.
                object: Row output of the SQL request, in JSON format, or if error, details returned from the request.
            """
            log = True if 'log' not in kwargs else bool(kwargs['log'])
            user = self.__rc__.get_first_valid_user(user)
            if not biscuits: biscuits = list(self.__rc__.biscuits) 
            # not true, if table is public_append or public_write
            # if biscuits == []:  raise SxTArgumentError('A biscuit with INSERT permissions must be included.', logger=self.__rc__.logger)
            
            if log: self.__rc__.logger.info(f'Inserting SQL:\n{sql_text}\n')
            success, response = user.base_api.sql_dml(sql_text=sql_text, biscuits=biscuits, app_name=self.__rc__.application_name, resources=[self.__rc__.table_name])
            if log and success:     self.__rc__.logger.info(   f'    Success: {response}')
            if log and not success: self.__rc__.logger.warning(f'    Failure: {response}')
            if not success: self.__rc__.__lasterr__ = self.__rc__.SXTExceptions.SxTQueryError(response)
            return success, response
        

        def list_of_dicts(self, list_of_dicts:list = [{}], biscuits:list = None, user:SXTUser = None, **kwargs) -> tuple[bool, dict]:
            """--------------------
            Turns a list of dictionaries into multiple distinct INSERT statements and submits for insertion to this resource on the Space and Time Network.

            Each row (dictionary) in the list will be inserted individually, thus can contain a different assortment of columns
            and data to insert.  This is intended for light-weight inserts of a few thousand rows.  For large-data inserts of streaming 
            data, check out Space and Time's Kafka streaming service at  https://docs.spaceandtime.io/reference  under Kafka.

            Args:
                list_of_dicts (str): List of dictionaries, each representing a row of name/value pairs to insert.
                biscuits (list): List of biscuits to authorize the request. Defaults to all biscuits added to the object.
                user (SXTUser): User who will execute the request. Defaults to the default user.

            Returns: 
                bool: Success flag, True if the data was fully inserted, False if any of the records failed.
                dict: Summary of the insert process, including an error log with any failed insert SQL and individual errors.
            """
            return self.with_list_of_dicts(list_of_dicts, biscuits, user, **kwargs)


        def with_list_of_dicts(self, list_of_dicts:list = [{}], biscuits:list = None, user:SXTUser = None, **kwargs) -> tuple[bool, dict]:
            """--------------------
            Turns a list of dictionaries into multiple distinct INSERT statements and submits for insertion to this resource on the Space and Time Network.

            Each row (dictionary) in the list will be inserted individually, thus can contain a different assortment of columns
            and data to insert.  This is intended for light-weight inserts of a few thousand rows.  For large-data inserts of streaming 
            data, check out Space and Time's Kafka streaming service at  https://docs.spaceandtime.io/reference  under Kafka.

            Args:
                list_of_dicts (str): List of dictionaries, each representing a row of name/value pairs to insert.
                biscuits (list): List of biscuits to authorize the request. Defaults to all biscuits added to the object.
                user (SXTUser): User who will execute the request. Defaults to the default user.

            Returns: 
                bool: Success flag, True if the data was fully inserted, False if any of the records failed.
                dict: Summary of the insert process, including an error log with any failed insert SQL and individual errors.
            """
            err_rtn = []
            good = err = 0
            row_count = len(list_of_dicts)
            self.__rc__.logger.info(f'INSERT {row_count} rows into {self.__rc__.resource_name}...')

            for row in list_of_dicts:
                cols = list(row.keys())
                data = [self.__rc__.safe_column_value(r) for r in row.values()]

                sql_text = f"INSERT INTO {self.__rc__.resource_name} ({ ', '.join(cols) }) \n VALUES \n ({ ', '.join(data) })"
                tries = 0
                success = False
                while success == False:
                    success, result = self.with_sqltext(sql_text=sql_text, biscuits=biscuits, user=user, log=False)
                    if not success: 
                        if len(result)>=1 and 'text' in result[0] and 'Duplicate key during INSERT' in result[0]['text']: break # no point in retrying this
                        time.sleep(2)
                    if tries >=3: break
                    tries +=1

                if success: good +=1
                else: 
                    err +=1
                    self.__rc__.logger.warning(f'    Error during insert: {sql_text[:sql_text.find("(")-1]}...')
                    err_rtn.append((result, sql_text))
            
                self.__rc__.logger.info(f'    {self.__rc__.resource_name} Inserted Row {good+err} of {row_count} ({(good+err)/row_count:.0%}) - Successes: {good}  Erred: {err}')

            self.__rc__.logger.info(f'INSERT into {self.__rc__.resource_name} complete - Total Rows: {good+err},  Successes: {good},  Erred: {err}')
            if not err==0: self.__rc__.__lasterr__ = self.__rc__.SXTExceptions.SxTQueryError(err_rtn)
            return err==0, {'rows': good+err, 'successes':good, 'errors':err, 'error_list':err_rtn }


        def list_of_dicts_batch(self, list_of_dicts:list = [{}], biscuits:list = None, user:SXTUser = None, rows_per_batch:int = 500, **kwargs) -> tuple[bool, dict]:
            """--------------------
            Turns a list of dictionaries into batched INSERT statements containing <rows_per_batch> rows per INSERT, and submits for insertion to this resource on the Space and Time Network.

            Batching multiple rows per insert requires all columns to be consistently present for all rows, and in the same order, or the 
            insert will error.  Each batch will be filled with rows up to rows_per_batch, and the insert will be submitted as one transaction, 
            making the operation all-or-nothing per batch. If you submit more total rows than the rows_per_batch, rows will be inserted in 
            multiple batches, each in it's own transaction, making multiple all-or-nothing transactions. This means the final batch will 
            typically contain fewer rows than rows_per_batch.

            This method is higher performance, but less flexible than individual inserts, making it more suitable for large-scale data loads
            with more controled inputs.  There is no hard limit to the number of rows_per_batch, however given the all-or-nothing nature of the 
            batching, it is recommended that rows_per_batch be kept under 1000 to minimize errors.

            Args:
                list_of_dicts (str): List of dictionaries, each representing a row of name/value pairs to insert.
                biscuits (list): List of biscuits to authorize the request. Defaults to all biscuits added to the object.
                user (SXTUser): User who will execute the request. Defaults to the default user.
                rows_per_batch (int): Number of rows to insert per batch. Defaults to 500.

            Returns: 
                bool: Success flag, True if the data was fully inserted, False if any of the records failed.
                dict: Summary of the insert process, including an error log with any failed insert SQL and individual errors.
            """
            err_rtn = []
            good = err = 0
            row_count = len(list_of_dicts)
            self.__rc__.logger.info(f'INSERT {row_count} rows into {self.__rc__.resource_name}...')
            if len(list_of_dicts) == 0: 
                self.__rc__.logger.warning(f'Nothing to insert, skipping')
                return True, { 'Batches': 0, 'successes':0, 'errors':0, 'error_list':[], 'rows':0 }

            # this won't work unless there's an authenticated user:
            if user is None: user = self.__rc__.user
            if user is None or user.access_expired: 
                msg = 'Error: USER provided is access expired or not supplied, please login, provide a SXTUser and try again.'
                self.__rc__.logger.error(msg)
                return False, msg

            # ----
            # build all the insert batches first, so we don't start something we can't finish:

            # determine the column order using the first row:
            cols = list(list_of_dicts[0].keys())

            # create list of rows, formatted, with consistent col order and ready for insert
            list_of_rows = ([ f"({', '.join( [self.__rc__.safe_column_value( d[col] ) for col in cols] )})" for d in list_of_dicts])
            
            # create batches
            batches = []
            for row in range(0, len(list_of_rows), rows_per_batch):
                batches.append( '\n,'.join(list_of_rows[row:row+rows_per_batch]) )

            # ----
            # execute the batches 
            sql_statements = []
            for batch in batches:
                sql_text = f"INSERT INTO {self.__rc__.resource_name} ({ ', '.join(cols) }) \n VALUES \n {batch}"
                sql_statements.append(sql_text)
                tries = 0
                success = False
                self.__rc__.logger.debug(f'/n{sql_text}')
                while success == False:
                    success, result = self.with_sqltext(sql_text=sql_text, biscuits=biscuits, user=user, log=False)
                    if not success: 
                        if len(result)>=1 and 'text' in result[0] and 'Duplicate key during INSERT' in result[0]['text']: break # no point in retrying this
                        time.sleep(2)
                    if tries >=3: break
                    tries +=1

                if success: good +=1
                else: 
                    err +=1
                    self.__rc__.logger.warning(f'    Error during insert: {sql_text[:sql_text.find("(")-1]}...')
                    err_rtn.append((result, sql_text))
            
                self.__rc__.logger.info(f'    {self.__rc__.resource_name} Inserted BATCH {good+err} of {math.ceil(row_count/rows_per_batch)} ({(good+err)/math.ceil(row_count/rows_per_batch):.0%}) - Successes: {good}  Erred: {err}')

            self.__rc__.logger.info(f'INSERT into {self.__rc__.resource_name} complete - Total Rows: {len(list_of_dicts)} ({rows_per_batch} rows per batch), Total Batches: {good+err},  Successes: {good},  Erred: {err}')
            if not err==0: self.__rc__.__lasterr__ = self.__rc__.SXTExceptions.SxTQueryError(err_rtn)
            return err==0, { 'Batches': good+err, 'successes':good, 'errors':err, 'error_list':err_rtn, 'rows':len(list_of_rows), 'sql_statements':sql_statements }



    class __upd__():
        def __init__(self, resource:SXTResource) -> None:
            self.__rc__ = resource
            self.__ins__ = self.__rc__.__ins__(resource)

        def with_sqltext(self, sql_text:str, biscuits:list = None, user:SXTUser = None, **kwargs) -> (bool, dict):
            """--------------------
            Submits a single UPDATE statement to the Space and Time network.  Note, while using the table Primary Key 
            is recommended, it is not required.

            Args:
                sql_text (str): UPDATE statement to submit to the SxT Network.
                biscuits (list): List of biscuits to authorize the request. Defaults to all biscuits added to the object.
                user (SXTUser): User who will execute the request. Defaults to the default user.

            Returns: 
                bool: Success flag, True if the data was fully updated, False if any of the records failed.
                object: Row output of the SQL request, in JSON format, or if error, details returned from the request.
            """
            log = True if 'log' not in kwargs else bool(kwargs['log'])
            user = self.__rc__.get_first_valid_user(user)
            if not biscuits: biscuits = list(self.__rc__.biscuits) 
            
            if log: self.__rc__.logger.info(f'Updating SQL:\n{sql_text}\n')
            sql_text = self.__rc__.replace_all(sql_text, {'table_name':self.__rc__.resource_name, 'resource_name':self.__rc__.resource_name} )
            success, response = user.base_api.sql_dml(sql_text=sql_text, biscuits=biscuits, app_name=self.__rc__.application_name, resources=[self.__rc__.table_name])
            if log and success:     self.__rc__.logger.info(   f'    Success: {response}')
            if log and not success: self.__rc__.logger.warning(f'    Failure: {response}')
            if not success: self.__rc__.__lasterr__ = self.__rc__.SXTExceptions.SxTQueryError(response)
            return success, response
        

        def with_list_of_dicts(self, pk_column:str, list_of_dicts:list = [{}], upsert:bool = False, biscuits:list = None, user:SXTUser = None, **kwargs) -> tuple[bool, dict]:
            """--------------------
            Turns a list of dictionaries into multiple UPDATE statements and submits for insertion to this resource on the Space and Time Network.

            Each row (dictionary) in the list will be coverted to an update statement individually, thus can contain a different 
            assortment of columns and data to update. Rows updated this way are always identified by the unique Primary Key, 
            so the pk_column must be specified, must match the PK column name in the table definition, and must appear in every 
            row in the list_of_dicts.  To perform arbitrary UPDATES against multiple rows, us the "with_sqltext()" function.
            This is intended for light-weight use of a few thousand rows.  For large-data processing of streaming data, check out
            Space and Time's Kafka streaming service at  https://docs.spaceandtime.io/reference  under Kafka.

            Args:
                pk_column (str): Column name for the unique primary key (PK) of the table.
                list_of_dicts (str): List of dictionaries, each representing a row of name/value pairs to insert.
                upsert (bool): If true, will insert any missing records instead of warning.
                biscuits (list): List of biscuits to authorize the request. Defaults to all biscuits added to the object.
                user (SXTUser): User who will execute the request. Defaults to the default user.

            Returns: 
                bool: Success flag, True if the data was fully inserted, False if any of the records failed.
                dict: Summary of the insert process, including an error log with any failed insert SQL and individual errors.
            """
            err_rtn = []
            inserts = []
            good = err = 0
            row_count = len(list_of_dicts)
            self.__rc__.logger.info(f'UPDATING {row_count} rows into {self.__rc__.resource_name}...')

            for row in list_of_dicts:
                early_error = False
                insert_row = False
                cols = [v.lower() for v in row.keys()]

                if pk_column.lower() not in cols: # PK not in column list
                    early_error = True
                    result = f'Row {good+err+1} - Primary Key (PK) column not found in row.'
                elif len(cols) < 2: # ONLY PK in column list (nothing to update)
                    early_error = True
                    result = f'Row {good+err+1} - No update-able data found.'

                # build update statement
                sql_text = ''
                if not early_error:
                    data = [f" {n} = {self.__rc__.safe_column_value(v)}" for n,v in row.items() if n.lower() != pk_column.lower() ]
                    update_where = f'{pk_column} = {self.__rc__.safe_column_value( row[pk_column] )}'
                    update_set = ' ' + '\n,'.join(data)
                    sql_text = f"UPDATE {self.__rc__.resource_name} SET \n{update_set}\nWHERE {update_where}"
                
                tries = 0
                success = False
                while success == False:
                    if early_error: break
                    if tries >3: break
                    success, result = self.with_sqltext(sql_text=sql_text, biscuits=biscuits, user=user, log=False)
                    if not success: 
                        time.sleep(2)
                    tries +=1

                # add to upsert if flagged, and record didn't exist
                if success and len(result) > 0 and result[0] == {'UPDATED': 0}:
                    if upsert: 
                        inserts.append(row)
                        insert_row = True
                    else:
                        result = f'Row {good+err+1} - Primary Key (PK) not found in table: {update_where}'
                        success = False

                if not insert_row:
                    if success: 
                        good +=1
                    else: 
                        err +=1
                        self.__rc__.logger.warning(f'    Error during update: {sql_text[:sql_text.find("SET")-1]}...')
                        err_rtn.append((result, sql_text))
                
                    self.__rc__.logger.info(f'    {self.__rc__.resource_name} Updated Row {good+err} of {row_count} ({(good+err)/row_count:.0%}) - Successes: {good}  Erred: {err}')

            if upsert:  # send missing rows to insert
                success, results = self.__rc__.insert.with_list_of_dicts(list_of_dicts = inserts, biscuits = biscuits, user = user, **kwargs)
                good += results['successes'] 
                err += results['errors']
                err_rtn.extend( results['error_list'] )

            self.__rc__.logger.info(f'UPDATE {self.__rc__.resource_name} complete - Total Rows: {good+err},  Successes: {good},  Erred: {err}')
            if not err==0: self.__rc__.__lasterr__ = self.__rc__.SXTExceptions.SxTQueryError(err_rtn)
            return err==0, {'rows': good+err, 'successes':good, 'errors':err, 'error_list':err_rtn }
        

    def delete(self, sql_text:str = None, where:str = '0=1', user:SXTUser = None, biscuits:list = None) -> tuple[bool, dict]:
        """--------------------
        Deletes records from the table, with a required WHERE statement.

        Note, some tables in the space and time network are immutable and cannot be changed.

        Args: 
            sql_text (str): If set, the sql_text is simply passed thru to the network directly as a DML request.
            where (str): A WHERE statement to limit rows deleted. This defaults to a zero-delete statement, so must be overridden to execute a meaningful delete. 
            user (SXTUser): User who will execute the request. Defaults to the default user.
            biscuits (list): List of biscuits required to authorize this request. 

        Returns: 
            bool: Success flag, True if the data was fully inserted, False if any of the records failed.
            object: Row output of the SQL request, as dict, or if error, details returned from the request.
        """
        user = self.get_first_valid_user(user)
        if not biscuits: biscuits = list(self.biscuits) 
        if biscuits == []: 
            raise SxTArgumentError('A biscuit with DELETE permissions must be included.', logger=self.logger)
        if len(where) >0 and not str(where).strip().startswith('where'): where = f' WHERE {where} '
        if not sql_text: sql_text = f"DELETE FROM {self.table_name} {where}"
        self.logger.info(f'DELETING: {sql_text}')
        success, results = user.base_api.sql_dml(sql_text=sql_text, biscuits=biscuits, app_name=self.application_name, resources=[self.table_name])
        time.sleep(1)
        if not success: self.__lasterr__ = self.SXTExceptions.SxTQueryError(results)
        return success, results

    



class SXTView(SXTResource):
    def __init__(self, name:str='', from_file:Path=None, default_user:SXTUser = None, 
                 private_key:str = '', new_keypair:bool = False, key_manager:SXTKeyManager = None,
                 application_name:str = None, start_time:datetime = None,
                 default_local_folder:Path = None, table_biscuit:SXTBiscuit = None,
                 logger:logging.Logger = None, SpaceAndTime_parent:object = None) -> None:
        """--------------------
        Creates a new Space and Time View object.

        Accepts a good number of settings during init, either individually (name, private_key,
        etc.) or use from_file to pass in Path to a save() file to reload previous config.
        Similarly, object parameters can be passed in individually (application_name, logger, 
        key_manager, default_user) or pass in the SpaceAndTime_parent object, and those objects
        will be inherited automatically.  The SpaceAndTime parameters are loaded first, 
        overridden by anything in the from_file, overridden by individual parameters.

        Args:
            name (str): Name of Schema.ViewName
            from_file (Path): Path location of a saved file to load from.
            default_user (SXTUser): User to use when no other user is specified.
            private_key (str): Private key for the Resource (not user), in Base64, Hex, or Binary.
            new_keypair (bool): If True, creates a new keypairs, overriding key_manager but not private_key (if set).
            key_manager (SXTKeyManager): Key manager object
            application_name (str): Name of the application, for logging and Space And Time query logging (if enabled).
            start_time (datetime): Starting time of the process (for uniformity across objects).
            default_local_folder (Path): default local path for saving / loading files.
            logger (Logger): Python Logger object, with which to log all activity.
            SpaceAndTime_parent (SpaceAndTime): parent SpaceAndTime class object to inherit default_user, key_manager, application_name, and logger.
        """
        self.resource_type = SXTResourceType.VIEW
        self.__foname__ = 'views'
        super().__init__(name, from_file, default_user, private_key, new_keypair, key_manager, application_name, start_time, default_local_folder, logger, SpaceAndTime_parent)
        self.__with__=  {"public_key":"{public_key}"}
        if table_biscuit: self.table_biscuit = table_biscuit
        self.__existfunc__ = self.user.base_api.discovery_get_views
        
    @property
    def view_name(self) -> str:
        return self.resource_name
    @view_name.setter
    def view_name(self, value):
        self.resource_name = value

    @property
    def table_biscuit(self) -> SXTBiscuit:
        rtn = [b for b in self.biscuits if b.__parentbiscuit__]
        if len(rtn) >0: 
            return rtn[0]
        else: 
            return None
    @table_biscuit.setter
    def table_biscuit(self, value):
        if type(value) == list and len(value) >0: value = value[0]
        if len(value)==0: return None
        if not type(value) == SXTBiscuit: 
            raise SxTArgumentError('Table_biscuit must be of type SXTBiscuit or a list of SXTBiscuits.')
        for biscuit in self.biscuits:
            if biscuit.__parentbiscuit__: biscuit=None 
        self.biscuits = [b for b in self.biscuits if b]
        value.__parentbiscuit__ = True
        self.biscuits.append(value) 

    @property
    def create_ddl_sample(self) -> str:
        return """
        CREATE VIEW {view_name} 
        {with_statement} 
        AS
        SELECT *
        FROM MySchema.MyTable """
    
    def has_with_statement(self, create_ddl:str) ->bool:
        """-------------------
        Returns True/False as to whether supplied Create Resource SQL has a WITH statement.
        
        Args:
            create_ddl (str): The Create Resource DDL / SQL to analyze for a WITH statement.

        Returns: 
            bool: True if the WITH statement was found, FALSE if not. 
        """
        create_ddl = create_ddl.lower().strip().replace('\n',' ').replace('\t',' ').replace('   ',' ').replace('  ',' ').replace('  ',' ')
        if '{with_statement}' in create_ddl or '{with}' in create_ddl: return True
        if 'with' not in create_ddl.lower(): return False
        pass 
        r6 = '' # rolling 6 chars
        for i in range(0, len(create_ddl)-6, 1):
            r6 = create_ddl[i:i+6]
            if r6[1:5].lower() == 'with' and not r6[0:1].isalnum() and not r6[5:6].isalnum(): return True
            if r6[1:5].lower() == ' as ': return False
        return False
    



class SXTMaterializedView(SXTResource):
    __ri__: int 

    def __init__(self, name:str='', from_file:Path=None, default_user:SXTUser = None, 
                 private_key:str = '', new_keypair:bool = False, key_manager:SXTKeyManager = None,
                 application_name:str = None, start_time:datetime = None,
                 default_local_folder:Path = None,
                 logger:logging.Logger = None, SpaceAndTime_parent:object = None) -> None:
        """--------------------
        Creates a new Space and Time Materialized View object.

        Accepts a good number of settings during init, either individually (name, private_key,
        etc.) or use from_file to pass in Path to a save() file to reload previous config.
        Similarly, object parameters can be passed in individually (application_name, logger, 
        key_manager, default_user) or pass in the SpaceAndTime_parent object, and those objects
        will be inherited automatically.  The SpaceAndTime parameters are loaded first, 
        overridden by anything in the from_file, overridden by individual parameters.

        Args:
            name (str): Name of Schema.ViewName
            from_file (Path): Path location of a saved file to load from.
            default_user (SXTUser): User to use when no other user is specified.
            private_key (str): Private key for the Resource (not user), in Base64, Hex, or Binary.
            new_keypair (bool): If True, creates a new keypairs, overriding key_manager but not private_key (if set).
            key_manager (SXTKeyManager): Key manager object
            application_name (str): Name of the application, for logging and Space And Time query logging (if enabled).
            start_time (datetime): Starting time of the process (for uniformity across objects).
            default_local_folder (Path): default local path for saving / loading files.
            logger (Logger): Python Logger object, with which to log all activity.
            SpaceAndTime_parent (SpaceAndTime): parent SpaceAndTime class object to inherit default_user, key_manager, application_name, and logger.
        """
        self.resource_type = SXTResourceType.MATERIALIZED_VIEW
        self.__foname__ = 'mat_views'
        super().__init__(name, from_file, default_user, private_key, new_keypair, key_manager, application_name, start_time, default_local_folder, logger, SpaceAndTime_parent)
        self.__ri__ = 1440
        self.__allprops__.insert(2, 'refresh_interval')
        self.__with__= {"public_key":"{public_key}", "refresh_interval":"{refresh_interval}"}
        self.__existfunc__ = self.user.base_api.discovery_get_views
        
    @property
    def matview_name(self) ->str:
        return self.resource_name
    @matview_name.setter
    def matview_name(self, value):
        self.resource_name = value

    @property
    def refresh_interval(self) -> int:
        return self.__ri__
    @refresh_interval.setter
    def refresh_interval(self, value):
        if value >= 1440: 
            self.__ri__ = value 
        else:
            raise SxTArgumentError('Current limit to a Materialized View refresh is once every 24 hours // 1440 minutes', logger=self.logger)

    @property
    def create_ddl_sample(self) -> str:
        return """
        CREATE MATERIALIZED VIEW {view_name} 
        {with_statement} 
        AS
        SELECT *
        FROM MySchema.MyTable """
    
    def has_with_statement(self, create_ddl:str) ->bool:
        """-------------------
        Returns True/False as to whether supplied Create Resource SQL has a WITH statement.
        
        Args:
            create_ddl (str): The Create Resource DDL / SQL to analyze for a WITH statement.

        Returns: 
            bool: True if the WITH statement was found, FALSE if not. 
        """
        create_ddl = create_ddl.lower().strip().replace('\n',' ').replace('\t',' ').replace('   ',' ').replace('  ',' ').replace('  ',' ')
        if '{with_statement}' in create_ddl or '{with}' in create_ddl: return True
        if 'with' not in create_ddl.lower(): return False
        pass 
        r6 = '' # rolling 6 chars
        for i in range(0, len(create_ddl)-6, 1):
            r6 = create_ddl[i:i+6]
            if r6[1:5].lower() == 'with' and not r6[0:1].isalnum() and not r6[5:6].isalnum(): return True
            if r6[1:5].lower() == ' as ': return False
        return False
    




if __name__ == '__main__':
    from pprint import pprint
    print('\n', '-=-='*10, '\n' )


    # test creating insert statements, without needing to connect to Space and Time initially
    chad = SXTUser('.env')
    success, response = chad.authenticate()
    
     
    testtable = SXTTable(name='SXTTEMP.DELETE_TEST', private_key=os.environ['RESOURCE_PRIVATE_KEY'], default_user=chad)
    testtable.add_biscuit('Admin', testtable.PERMISSION.ALL)
    insertdata = [{'PK_ID':r, 'TEST_GROUP':f"{r}", 'OTHER_DATA':None if r%2==0 else f"{r}"} for r in range(0,100)]

    print(testtable.get_column_names())

    testtable.delete(where='1=1', user=chad)
    success, summary = testtable.insert.list_of_dicts_batch(insertdata, rows_per_batch=15, user=chad)

    pass 


    # Create a user and authenticate:
    suzy = SXTUser('.env', authenticate=True)


    # Create a table, using a new keypair
    tableA = SXTTable(name='SXTTEMP.New_TableName', new_keypair=True, default_user=suzy)
    tableA.add_biscuit('Read', tableA.PERMISSION.SELECT)
    tableA.add_biscuit('Load', tableA.PERMISSION.SELECT, tableA.PERMISSION.INSERT, tableA.PERMISSION.UPDATE, tableA.PERMISSION.DELETE, tableA.PERMISSION.MERGE)
    tableA.add_biscuit('Admin', tableA.PERMISSION.ALL)
    tableA.create_ddl = """
        CREATE TABLE {table_name} 
        ( MyID         int
        , MyName       varchar
        , MyDate       date
        , Primary Key  (MyID) 
        )  
    """
    print( tableA.get_column_names() )

    tableA.save()  # save to local file, to prevent lost keys
    if not tableA.exists: 
        success, results = tableA.create()  # Create table on Space and Time network
    

    if success:

        # generate some dummy data
        cols = ['MyID','MyName','MyDate']
        data = [[i, chr(64+i), f'2023-09-0{i}'] for i in list(range(1,10))]

        # perform insert
        tableA.insert(columns=cols, data=data)
        tableA.insert(sql_text= f"Insert into {tableA.table_name} values (20, 'manual test', '2023-01-01')" )

        # select records back, just to verify
        success, results = tableA.select()
        pprint(results if success else f'Error! {results}')


        # create a view based on the above table, with the same keys
        viewA = SXTView(name="SXTTEMP.New_ViewName", default_user=suzy, private_key=tableA.private_key)
        viewA.add_biscuit('Admin', viewA.PERMISSION.ALL)
        viewA.table_biscuit = tableA.get_biscuit('Admin')
        viewA.create_ddl = "CREATE VIEW {view_name} {with_statement} AS SELECT * from " + tableA.table_name
        
        success, results = viewA.create()
        pprint(f'Success! {results}' if success else f'Error! {results}')

        if success:
            success, results = viewA.select()
            pprint(results if success else f'Error! {results}')
        
        # drop the view
        success, results = viewA.drop() 
        pprint(f'Success! {results}' if success else f'Error! {results}')

    # drop the table
    success, results = tableA.drop()
    print( f'success?  {success}\nData: {results}' )




    # find the latest save file, load it, and perform a drop (in cases it was interrupted above):
    if False: 
        tableA = SXTTable(default_user=suzy)
        tableA.load(filepath = './resources/table--SXTTEMP.New_TableName--v202309271907',  find_latest = True)
        viewA = SXTView(name='SXTTEMP.New_ViewName', private_key=tableA.private_key, default_user=suzy)
        viewA.add_biscuit('admin', viewA.PERMISSION.ALL)
        viewA.table_biscuit = tableA.get_biscuit('admin')
        success, result = viewA.drop()
        success, result = tableA.drop()

    pass 