import logging, json, sys
from pathlib import Path
from datetime import datetime
from biscuit_auth import KeyPair, PrivateKey, PublicKey, Authorizer, Biscuit, BiscuitBuilder, BlockBuilder, Rule, DataLogError

# done fighting with this, sorry
sxtpypath = str(Path(__file__).parent.resolve())
if sxtpypath not in sys.path: sys.path.append(sxtpypath)
from sxtexceptions import SxTArgumentError, SxTFileContentError, SxTBiscuitError, SxTKeyEncodingError
from sxtenums import SXTPermission, SXTKeyEncodings
from sxtkeymanager import SXTKeyManager



class SXTBiscuit():
    """Definition of a single biscuit."""

    logger: logging.Logger = None 
    domain: str = 'sxt'
    name: str = 'biscuit_name'
    key_manager: SXTKeyManager = None
    GRANT = SXTPermission
    ENCODINGS = SXTKeyEncodings
    __cap:dict = {'schema.resource':['permission1', 'permission2']}
    __bt: str = ''
    __lastresource: str = ''
    __manualtoken:bool = False
    __parentbiscuit__:bool = False
    __defaultresource__:str = ''
    
    def __init__(self, name:str = '', private_key: str = None, new_keypair: bool = False, 
                 from_file: Path = None, logger:logging.Logger = None, 
                 biscuit_token:str = None, default_resource:str = None) -> None:
        if logger: 
            self.logger = logger 
        else: 
            self.logger = logging.getLogger()
            self.logger.setLevel(logging.INFO)
            if len(self.logger.handlers) == 0: 
                self.logger.addHandler( logging.StreamHandler() )
        self.logger.info('-'*30 + '\nNew SXT Biscuit initiated')
        self.key_manager = SXTKeyManager(logger=self.logger, encoding=SXTKeyEncodings.BASE64)
        if new_keypair: self.key_manager.new_keypair()
        if private_key: self.private_key = private_key
        self.__cap = {}
        if name: self.name = name 
        if default_resource: self.__defaultresource__ = default_resource
        if from_file and Path(from_file).exists: self.load(from_file)
        if biscuit_token: 
            self.__manualtoken = True 
            self.__bt = biscuit_token
            self.logger.info('manual biscuit token accepted as-is, not calculated or verified.')
            

    def __str__(self):
        return '\n'.join([f"{str(n).rjust(25)}: {v}" for n,v in  dict(self.to_json(True, True)).items()])
    
    def __repr__(self):
        return '\n'.join([f"{str(n).rjust(25)}: {v}" for n,v in  dict(self.to_json(False, True)).items()])

    def __len__(self):
        return 1

    @property
    def biscuit_text(self):
        b = []
        for resource, permissions in self.__cap.items():
            for permission in sorted(permissions):
                b.append(f'{self.domain}:capability("{permission}", "{str(resource).lower()}");')
        return '\n'.join(b)

    @property
    def biscuit_token(self) ->str:
        if self.__manualtoken: return self.__bt
        if not self.private_key or not self.biscuit_text: 
            self.__bt = ''
            return ''
        if not self.__bt: self.__bt = self.regenerate_biscuit_token()
        return self.__bt
    
    @property
    def biscuit_json(self) -> dict:
        return self.__cap

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
    def default_resource(self) ->str: 
        return str(self.__defaultresource__)
    @default_resource.setter
    def default_resource(self, value):
        if type(value)==str: 
            self.__defaultresource__ = value
        else:
            raise ValueError('default_resource must be set to a string.')


    def new_keypair(self) -> dict:
        return self.key_manager.new_keypair()


    def regenerate_biscuit_token(self) -> dict:
        """--------------------
        Regenerates the biscuit_token from class.biscuit_text and class.private_key. 

        For object consistency, this only leverages the class objects, so there are no arguments.  
        To build the biscuit_text, clear_capabilities() and then add_capability(), or if you want to import 
        an existing datalog file, you can load capabilities_from_text(). This function will error without 
        a valid private_key and biscuit_text.

        Args: 
            None

        Returns: 
            str: biscuit_token in base64 format. 
        """
        if not self.private_key:
            raise SxTArgumentError("Private Key is required to create a biscuit", logger=self.logger)
        
        biscuit_text = self.biscuit_text 
        if not biscuit_text:
            raise SxTArgumentError('Biscuit_Text is required to create a biscuit. Try to add_capability() and inspect biscuit_text to verify.', logger=self.logger)

        try:
            private_key_obj = PrivateKey.from_hex(self.key_manager.private_key_to(SXTKeyEncodings.HEX))
            biscuit = BiscuitBuilder(self.biscuit_text).build(private_key_obj)
            return biscuit.to_base64() 
        except DataLogError as ex:
            errmsg = ex
        raise SxTBiscuitError(errmsg, logger=self.logger)


    def validate_biscuit(self, biscuit_base64:str, public_key = None) -> str:
        if not public_key: public_key = self.public_key
        public_key = self.convert_key(public_key, self.get_encoding_type(public_key), SXTKeyEncodings.HEX )
        try:
            return Biscuit.from_base64( data=biscuit_base64, root=PublicKey.from_hex( public_key ))
        except Exception as ex:
            self.logger.error(ex)
        raise SxTBiscuitError('Biscuit not validated with Public Key', logger=self.logger)


    def add_capability(self, resource:str, *permissions):
        """--------------------
        Adds a capability to the existing biscuit structure. 

        Args:
            resource (str): Resource (Schema.Resource) to which permissions are applied.
            permission (*): Any number of SXTPermission enums to GRANT to the resource. 

        Returns:
            int: Number of items added (excluding duplicates)

        Examples:
            >>> bb = SXTBiscuitBuilder()
            >>> bb.add_capability("Schema.TableA", "SELECT")
            1
            >>> bb.add_capability("Schema.TableA", "INSERT")
            True
            >>> bb.add_capability("Schema.TableA", "INSERT")
            False
        """
        if not resource: resource = self.__defaultresource__
        if not resource: resource = self.__lastresource
        if not resource: raise KeyError('must define a resource (schema.object) on which to assign permissions')
        self.__lastresource = resource
        if resource not in self.__cap: self.__cap[resource] = []
        if 'ALL' in self.__cap[resource] or '*' in self.__cap[resource]:
            self.logger.warning('Cannot add other permissions to a biscuit containing ALL permissions.  Request disregarded.')
            return self.__isall__(resource)
        initial_count = len(self.__cap[resource])
        process_count = 0
        final_permissions = []
        for permission in permissions: 
            process_count += 1
            if type(permission) == list: 
                if 'ALL' in permission: return self.__isall__(resource)
                final_permissions += list(permission)
                process_count += len(list(permission))-1
            else:
                if permission.name == 'ALL': return self.__isall__(resource)
                final_permissions.append(permission)
        self.__cap[resource] += [p.value for p in final_permissions]
        self.__cap[resource] = list(set(self.__cap[resource]))
        self.__bt = ''
        added_count = len(self.__cap[resource]) - initial_count
        self.logger.info(f'Added {added_count} permissions, from total {process_count} submitted ({process_count - added_count} duplicates)')
        return added_count

    def __isall__(self, resource):
        total_count = len(self.__cap[resource])
        self.__cap[resource] = ['*']
        self.logger.info(f'Added ALL permissions, replacing a total of {total_count} other permissions.')
        return 1
        

    def capabilities_from_text(self, biscuit_text:str) -> None:
        """--------------------
        Loads text into biscuit capabilities, for example, loading a datalog file directly.

        Args: 
            biscuit_text (str): Text to compile into capabilities.

        Results:
            str: biscuit_text that has been digested and re-processed.

        """
        biscuit_lines = str(biscuit_text).strip().split('\n')
        caps = {}
        self.logger.debug(f'Translating supplied text into biscuit capabilities...')
        for line in biscuit_lines:
            if line.strip().startswith(f'{self.domain}:capability'):
                c = line.split('"')
                if len(c) <5: 
                    raise SxTArgumentError('biscuit_text capabilities must have format  domain:capability("PERMISSION", "RESOURCE");')
                p = c[1] # permission
                r = c[3] # resource
                if r not in caps: caps[r] = []
                caps[r].append(p)
        for r in list(caps.keys()):
            caps[r] = list(set(caps[r]))
        self.__cap = caps
        self.__bt = ''
        self.logger.debug(f'Successfully translated biscuit_text to biscuit capabilities objects.')
        return None


    def capabilities_from_token(self, biscuit_token:str) -> None:
        raise NotImplementedError('Not implemented yet. Please check back later.')


    def clear_capabilities(self):
        """Clears all existing capabilities from the biscuit structure"""
        self.__cap = {}
        self.__bt = ''
        self.logger.debug('Clearing all biscuit capabilities')
        return None


    def to_json(self, mask_private_key:bool = True, add_tabs_to_biscuit_text:bool = False):
        """Exports content of biscuit to a json format.  WARNING, this can include private key."""
        tab = '\t' if add_tabs_to_biscuit_text else ''
        rtn = { 'private_key': getattr(self, 'private_key')[:6]+'...' if mask_private_key else getattr(self, 'private_key')
               ,'public_key' : getattr(self, 'public_key' )
               ,'biscuit_capabilities' : self.__cap
               ,'biscuit_token': self.biscuit_token
               ,'biscuit_text': f'\n{tab}' + str(self.biscuit_text).replace('\n',f'\n{tab}')
               }
        self.logger.debug(f'Translating object data to json')
        return dict(rtn)


    def save(self, filepath: Path = 'biscuits/biscuit_{resource}_{date}_{time}.json', overwrite:bool = False, resource:str = None) -> Path:
        """--------------------
        Saves biscuit information to a json file.

        The filepath will accept three different placholder texts: {resource}, {date}, and {time}.  
        This allows caller to easily create dynamically named biscuit files, reducing the likelihood of 
        overwriting biscuit files and thus losing keys.   It is best practice to leave overwrite to False
        and use placeholders to save different files, removing older save files only after validation
        the keys are not needed anymore.  

        Args:
            filepath (Path): Full file path which to save, with placeholders allowed.
            overwrite (bool): If True, will overwrite file if exists
            resource (str): Optional resource name for placeholder in filepath.  Defaults to last resource set in add_capability().
        
        Results:
            Path: Same as filepath, if successful
        """
        # TODO: add string.replace for resource, date, time
        filepath = Path(filepath).resolve()
        # do placeholder replacements
        if not resource: resource = self.__lastresource
        date = datetime.now().strftime('%Y%m%d')
        time = datetime.now().strftime('%H%M%S')
        filepath = Path(str(filepath).replace('{resource}', resource).replace('{date}',date).replace('{time}',time))
        if filepath.exists() and not overwrite: 
            raise FileExistsError(f'{filepath} already exists.  Set overwrite = True to overwrite automatically.')

        filepath.parent.mkdir(parents=True, exist_ok=True)
        self.logger.debug(f'Opening file to write: {filepath}...')
        with open(filepath, 'w') as fh:
            fh.write( json.dumps(self.to_json(False)).replace('\t','') )
        self.logger.debug(f'Data written to file.')
        return filepath
    

    def load(self, filepath: Path, resource:str = None, date:str = None, time:str = None) -> dict:
        """--------------------
        Loads a biscuit from correctly formated JSON file.

        The filepath will accept three different placholder texts: {resource}, {date}, and {time}.  
        This allows caller to easily create (and load) dynamically named biscuit files, reducing the 
        likelihood of overwriting biscuit files and thus losing keys.  It is best practice to leave 
        overwrite to False and use placeholders to save different files, removing older save files 
        only after validation the keys are not needed anymore.

        Args:
            filepath (Path): Full file path which to load from
            resource (str): Optional resource name for placeholder in filepath.  Defaults to last resource set in add_capability().
            date (str): Optional integer-only date (yyyymmdd) for placeholder in file path. Defaults to current date.
            time (str): Optional integer-only time (hhmmss) for placeholder in file path. Defaults to current time.

        Results:
            Path: Same as filepath, if successful
        """
        self.logger.info('Attempting to load biscuit definition from file...')
        filepath = Path(filepath).resolve()
        # do placeholder replacements
        if not resource: resource = self.__lastresource
        if not date: date = datetime.now().strftime('%Y%m%d')
        if not time: time = datetime.now().strftime('%H%M%S')
        filepath = Path(str(filepath).replace('{resource}', resource).replace('{date}',date).replace('{time}',time))
        # TODO: allow option for 'Most Recent" for date and time, which can look thru
        # the parent directory and find the file with the most recent {date} / {time}.
        # This will hopefully promote behavior of keeping history of keys, in case 
        # they're needed 
        
        if not filepath.exists: 
            raise FileNotFoundError(f'{filepath} not found.')
        try:
            self.logger.debug(f'Opening file: {filepath}...')
            with open(filepath, 'r') as fh:
                content = json.loads(fh.read())
            if 'private_key' not in content or 'biscuit_text' not in content: 
                raise SxTFileContentError 
        except (SxTFileContentError, json.JSONDecodeError):
              self.logger.error(f'File not loaded due to missing, malformed content, or simply unable to load JSON: \n{filepath}')
              return None
        try:
            new_key_encoding = self.key_manager.get_encoding_type(content['private_key'])
            new_private_key =  self.key_manager.convert_key(content['private_key'], new_key_encoding, SXTKeyEncodings.BYTES)
        except SxTArgumentError: 
            return None
        
        # Assign last, after all validation.  public_key, biscuit_text, biscuit_token all recalculate automatically.
        self.logger.info(f'File opened and parsed, loading data into current object.')
        self.capabilities_from_text(content['biscuit_text'])
        self.private_key = new_private_key
        return content
            