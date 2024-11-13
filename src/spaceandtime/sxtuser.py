import os, logging, datetime, random
from pathlib import Path
from dotenv import load_dotenv
from .sxtexceptions import SxTAuthenticationError, SxTArgumentError
from .sxtkeymanager import SXTKeyManager, SXTKeyEncodings
from .sxtbaseapi import SXTBaseAPI, SXTApiCallTypes 


class SXTUser():
    user_id: str = ''
    api_url: str = ''
    logger: logging.Logger = None 
    key_manager: SXTKeyManager = None
    ENCODINGS = SXTKeyEncodings
    base_api: SXTBaseAPI = None
    access_token: str = ''
    refresh_token: str = ''
    access_token_expire_epoch: int = 0
    refresh_token_expire_epoch: int = 0
    auto_reauthenticate:bool = False 
    start_time:datetime.datetime = None
    __bs: list = None
    __usrtyp__:list = None

    def __init__(self, dotenv_file:Path = None, user_id:str = None, 
                 user_private_key:str = None, api_url:str = None,
                 encoding:SXTKeyEncodings = None, authenticate:bool = False, 
                 application_name:str = None,
                 logger:logging.Logger = None, 
                 SpaceAndTime_parent:object = None,
                 **kwargs) -> None:
        
        # start with parent import
        if SpaceAndTime_parent:
            if not application_name: self.application_name = SpaceAndTime_parent.application_name
            if not logger: logger = SpaceAndTime_parent.logger
            self.start_time = SpaceAndTime_parent.start_time if SpaceAndTime_parent.start_time else datetime.datetime.now()

        if logger: 
            self.logger = logger 
        else: 
            self.logger = logging.getLogger()
            self.logger.setLevel(logging.INFO)
            if len(self.logger.handlers) == 0: 
                self.logger.addHandler( logging.StreamHandler() )
        self.logger.debug(f'SXT User instantiating...')

        encoding = encoding if encoding else SXTKeyEncodings.BASE64 
        self.key_manager = SXTKeyManager(private_key = user_private_key, encoding = encoding, logger=self.logger)
        self.base_api = SXTBaseAPI(logger = self.logger)
        self.__bs = []
        self.__usrtyp__ = {'type':'', 'timeout':datetime.datetime.now()}

        # from dotenv file, if exists
        dotenv_file = Path('./.env') if not dotenv_file and Path('./.env').resolve().exists() else dotenv_file
        if dotenv_file: self.load(dotenv_file)

        # overwrite userid, api_url, and private key (and public key, by extension), if supplied
        if user_private_key: self.private_key = user_private_key
        if user_id: self.user_id = user_id
        if api_url: self.api_url = api_url

        # secret option: make a test user_id if requested:
        if 'testuser' in kwargs: 
            self.user_id = 'testuser_' + kwargs['testuser'] + '_' + f"{random.randint(0,999999999999):012}"

        self.logger.info(f'SXT User instantiated: {self.user_id}')
        if authenticate: self.authenticate()


    @property
    def private_key(self) ->str :
        return self.key_manager.private_key
    @private_key.setter
    def private_key(self, value):
        self.key_manager.private_key = value 

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
    def access_token_expire_datetime(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(self.access_token_expire_epoch/1000)
    
    @property
    def refresh_token_expire_datetime(self) -> datetime.datetime: 
        return datetime.datetime.fromtimestamp(self.refresh_token_expire_epoch/1000)

    @property
    def access_expired(self) -> bool:
        return datetime.datetime.now() > self.access_token_expire_datetime

    @property
    def refresh_expired(self) -> bool:
        return datetime.datetime.now() > self.refresh_token_expire_datetime

    @property
    def user_type(self) -> str:
        if self.__usrtyp__['type'] == '' or self.__usrtyp__['timeout'] <= datetime.datetime.now():
            success, users = self.base_api.subscription_get_users()
            if success and self.user_id in users['roleMap']: 
                self.__usrtyp__['type'] = str(users['roleMap'][self.user_id]).lower()
                self.__usrtyp__['timeout'] = datetime.datetime.now() + datetime.timedelta(minutes=15)
                return self.__usrtyp__['type']
            else:
                return 'disconnected - authenticate to retrieve'
        else:
            return self.__usrtyp__['type']

    @property
    def recommended_filename(self) -> Path:
        filename = f'./users/{self.user_id}.env' 
        return Path(filename)
 

    @property
    def exists(self) -> bool:
        """Returns whether the user_id exists on the network."""
        success, response = self.base_api.auth_idexists(self.user_id)
        return True if str(response).lower() == 'true' else False


    def __validtoken__(self, name:str) -> dict:      
        if self.access_expired: return 'disconnected - authenticate to retrieve'
        success, response = self.base_api.auth_validtoken()
        if success and name in response: return response[name]
        else: return 'error - could not retrieve'  

    @property
    def subscription_id(self) -> str:
        return self.__validtoken__('subscriptionId')
    
    @property
    def is_trial(self) -> str:
        return self.__validtoken__('trial')
    
    @property
    def is_restricted(self) -> str:
        return self.__validtoken__('restricted')

    @property
    def is_quota_exceeded(self) -> str:
        return self.__validtoken__('quotaExceeded')
 



    def __str__(self):
        flds = {fld: getattr(self, fld) for fld in ['api_url','user_id','exists','private_key','public_key','encoding', 'subscription_id', 'is_trial', 'is_restricted', 'is_quota_exceeded']}
        flds['private_key'] = flds['private_key'][:6]+'...'
        return '\n'.join( [ f'\t{n} = {v}' for n,v in flds.items() ] )


    def new_keypair(self):
        """--------------------
        Generate a new ED25519 keypair, set class variables and return dictionary of values.

        Returns:
            dict: New keypair values

        Examples:
            >>> user = SXTUser()
            >>> user.new_keypair()
            ['private_key', 'public_key']
            >>> len( user.private_key )
            64
            >>> user.encoding = SXTKeyEncodings.BASE64
            >>> len( user.private_key )
            44
        """
        return self.key_manager.new_keypair()


    def load(self, dotenv_file:Path = None): 
        """Load dotenv (.env) file / environment variables: API_URL, USERID, USER_PUBLIC_KEY, USER_PRIVATE_KEY, optionally USER_JOINCODE, USER_KEY_SCHEME, APP_PREFIX.  
        
        Args:
            dotenv_file (Path): Path to .env file.  If not set, first default is the file ./.env, second defalut is to load existing environment variables.

        Returns: 
            None
        """
        load_dotenv(dotenv_file, override=True)
        self.api_url = os.getenv('API_URL')

        # add user_id from environment (including several options)
        for userid_var in ['SXT_USER_ID', 'SXT_USERID', 'USER_ID', 'USERID']:
            temp = os.getenv(userid_var)
            if temp: 
                self.user_id = temp
                break
        
        # add user private key from environment (including several options)
        for user_privatekey_var in ['SXT_USER_PRIVATE_KEY', 'SXT_USER_PRIVATEKEY', 'USER_PRIVATE_KEY', 'USER_PRIVATEKEY']:
            temp = os.getenv(user_privatekey_var)
            if temp: 
                self.private_key = temp
                break

        # TODO: Right now, only ED25519 authentication is supported.  Add Eth wallet support, or other future schemes
        # self.key_scheme = os.getenv('USER_KEY_SCHEME')
        
        loc = str(dotenv_file) if dotenv_file and Path(dotenv_file).exists() else 'default .env location'
        self.logger.info(f'dotenv loaded\n{ self }')
        return None


    def save(self, dotenv_file:Path = None):
        """Save dotenv (.env) file containing variables: API_URL, USERID, USER_PUBLIC_KEY, USER_PRIVATE_KEY, optionally USER_JOINCODE, USER_KEY_SCHEME, APP_PREFIX.  
        
        Args: \n
            dotenv_file -- full path to .env file, defaulting to ./users/{user_id}.env if not supplied. Note: to minimize losing keys, overwrites are disallowed. 

        Results: \n
            None
        """
        if not dotenv_file: dotenv_file = self.recommended_filename
        dotenv_file = Path(self.replace_all(str(dotenv_file))).resolve()
        if dotenv_file.exists():
            self.logger.error(f'File Exists: {dotenv_file}\nTo minimize lost keys, file over-writes are not allowed.')
            raise FileExistsError('To minimize lost keys, file over-writes are not allowed.')

        try:
            fieldmap = { 'api_url':'API_URL'
                        ,'user_id':'USERID'
                        ,'private_key':'USER_PRIVATE_KEY'
                        ,'public_key':'USER_PUBLIC_KEY'                        
                        }
                        
            # build insert string for env file
            hdr = '# -------- Below was added by the SxT SDK'
            lines = [hdr]
            for pyname, envname in fieldmap.items():
                lines.append( f'{envname}="{ getattr(self, pyname) }"' )

            dotenv_file = Path(dotenv_file)
            dotenv_file.parent.mkdir(parents=True, exist_ok=True)
            i=0

            if dotenv_file.exists():
                with open(dotenv_file.resolve(), 'r') as fh:    # open file
                    for line in fh.readlines():                 # read each line
                        val = str(line).split('=')[0].strip()   # get text before "="
                        if val and val != hdr and \
                           val not in list(fieldmap.values()):  # if text doesn't exist in fieldmap values
                            lines.insert(i,str(line).strip())   # add it, so it gets written to new file
                            i+=1                                # preserve the original order of the file

            # create (overwrite) file        
            with open(dotenv_file.resolve(), 'w') as fh:
                fh.write( '\n'.join(lines) )                
        
            self.logger.debug(f'saved dotenv file to: { dotenv_file }')
            self.logger.warning('THE SAVED FILE CONTAINS PRIVATE KEYS!')
            return None

        except Exception as err:
            msg = f'Attempting to write new .env file to {dotenv_file}\n{ str(err) }'
            self.logger.error(msg)
        raise FileNotFoundError(msg)


    def replace_all(self, mainstr:str, replace_map:dict = None) -> str:
        if not replace_map: replace_map = {'user_id':self.user_id, 'public_key':self.public_key, 'start_time':self.start_time.strftime('%Y-%m-%d %H:%M:%S')}
        if 'date' not in replace_map.keys(): replace_map['date'] = int(self.start_time.strftime('%Y%m%d'))
        if 'time' not in replace_map.keys(): replace_map['time'] = int(self.start_time.strftime('%H%M%S'))
        for findname, replaceval in replace_map.items():
            mainstr = str(mainstr).replace('{'+str(findname)+'}', str(replaceval))                    
        return mainstr



    def __settokens__(self, access_token:str, refresh_token:str, access_token_expire_epoch:int, refresh_token_expire_epoch:int):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.access_token_expire_epoch = access_token_expire_epoch
        self.refresh_token_expire_epoch = refresh_token_expire_epoch
        self.base_api.access_token = self.access_token


    def authenticate(self) -> str:
        return self.register_new_user()

    def register_new_user(self, join_code:str = None) -> str:
        """--------------------
        Authenticate to the Space and Time network, and store access_token and refresh_token.

        Args: 
            join_code (str): Optional to create a new user within an existing subscription.
        
        Returns:
            bool: Success flag (True/False) indicating the call worked as expected.
            object: Access_Token if successful, otherwise an error object.
        """
        if not (self.user_id and self.private_key):
            raise SxTArgumentError('Must have valid UserID and Private Key to authenticate.', logger=self.logger)
        
        try: 
            success, response = self.base_api.get_auth_challenge_token(user_id = self.user_id, joincode=join_code)
            if success:
                challenge_token = response['authCode']
                signed_challenge_token = self.key_manager.sign_message(challenge_token)
                success, response = self.base_api.get_access_token(user_id = self.user_id, 
                                                                   challange_token = challenge_token, 
                                                                   signed_challange_token = signed_challenge_token,
                                                                   public_key = self.public_key)
            if success:
                tokens = response
            else: 
                raise SxTAuthenticationError(str(response), logger=self.logger)
            if len( [v for v in tokens if v in ['accessToken','refreshToken','accessTokenExpires','refreshTokenExpires']] ) < 4:
                raise SxTAuthenticationError('Authentication produced incorrect / incomplete output', logger=self.logger)
        except SxTAuthenticationError as ex:
            return False, [ex]

        self.__settokens__(tokens['accessToken'], tokens['refreshToken'], tokens['accessTokenExpires'], tokens['refreshTokenExpires'])
        if join_code and ('disconnected' in str(self.subscription_id).strip() or str(self.subscription_id).strip() == ''): 
            success, response = self.join_subscription(join_code) 

        return True, self.access_token 


    def reauthenticate(self) -> str:
        """Re-authenticate an existing access_token to the Space and Time network."""
        if not self.refresh_expired:
            raise SxTArgumentError('Refresh token has expired', logger=self.logger)
        try:
            success, tokens = self.base_api.token_refresh(self.refresh_token)
            if not success:
                raise SxTAuthenticationError(str(tokens), logger=self.logger)
            if len( [v for v in tokens if v in ['accessToken','refreshToken','accessTokenExpires','refreshTokenExpires']] ) < 4:
                raise SxTAuthenticationError('Authentication produced incorrect / incomplete output', logger=self.logger)
        except SxTAuthenticationError as ex:
            return False, [ex]
        self.access_token = tokens['accessToken']
        self.refresh_token = tokens['refreshToken']
        self.access_token_expire_epoch = tokens['accessTokenExpires']
        self.refresh_token_expire_epoch = tokens['refreshTokenExpires']
        self.base_api.access_token = self.access_token
        return True, self.access_token 

    def execute_sql(self, sql_text:str, biscuits:list = None, app_name:str = None):
        """
        This is a duplicate of the "execute_query" method, provided for backwards compatibility.
        Use the more consistent "execute_query" to avoid future deprecation issues. 
        """
        return self.execute_query(sql_text=sql_text, biscuits=biscuits, app_name=app_name)

    def execute_query(self, sql_text:str, biscuits:list = None, app_name:str = None):
        return self.base_api.sql_exec(sql_text=sql_text, biscuits=biscuits, app_name=app_name)


    def generate_joincode(self, role:str = 'member'):
        """
        Generate an invite /joincode to join the inviting user's subscription.

        Args: 
            role (str): Role level to assign the new user. Can be member, admin, or owner.
        
        Returns:
            str: Joincode
        """
        success, results = self.base_api.subscription_invite_user(role)
        if not success:
            self.logger.error(str(results)) 
            return str(results)
        self.logger.info('Generated joincode')
        return results['text']
    

    def join_subscription(self, joincode:str):
        """
        Join an existing subscription to the Space and Time network, based on supplied JoinCode (expires after 24 hours).
        Note, joining a subscription will refresh both the access_token and refresh_token.
        """
        success, tokens = self.base_api.subscription_join(joincode=joincode)
        if success: 
            self.__settokens__(tokens['accessToken'], tokens['refreshToken'], tokens['accessTokenExpires'], tokens['refreshTokenExpires'])
            return True, 'Consumed join_code and joined subscription!'
        if not success:
            self.logger.error(str(tokens)) 
            return False, str(tokens)


    def leave_subscription(self) -> tuple[bool, dict]:   
        """
        Currently authenticated user leaves subscription.  Fails if the user is not authenticated.
        """
        if self.access_expired: return False, {"error":"disconnected - authenticate to leave subscription"}
        return self.base_api.subscription_leave()
        
    def remove_from_subscription(self, user_id_to_remove:str) -> tuple[bool, dict]:
        """
        Removes another user from the current user's subscription.  Current user must have more authority than the targeted user to remove.

        Args: 
            User_ID_to_Remove (str): ID of the user to remove from the current user's subscription.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json).
        """
        success, response = self.base_api.subscription_remove(user_id_to_remove)
        if success: 
            msg =f"Removed {user_id_to_remove} from subscription."
            self.logger.info(msg)
            return True, {"text": msg}
        else:
            self.logger.error(str(response)) 
            return False, response
        

    def get_subscription_users(self) -> tuple[bool, dict]:
        """
        Returns a list of all users in the current subscription.
        
        Args:
            None

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Dictionary of User_IDs and User Permission level in the subscription, or error as json.
        """
        success, response = self.base_api.subscription_get_users()
        if success: 
            return True, response
        else:
            self.logger.error(response) 
            return False, response



if __name__ == '__main__':

    # BASIC USAGE
    user = SXTUser(user_id = 'suzy')
    user.key_manager.new_keypair()
    user.save('test/suzy.env')
    print( user )

    suzy = SXTUser(encoding = SXTKeyEncodings.HEX)
    suzy.load('test/suzy.env')
    print( suzy )

    bill = SXTUser(user_id='bill', user_private_key='Z833BwZcwotJf4zVA89HlyvxH8xqAUOXzTcR1dWhsrk=')
    bill.save('test/bill.env')
    print( bill )

    stephen = SXTUser()
    stephen.authenticate()

    pass