import requests, logging, json, sys 
from pathlib import Path

# done fighting with this, sorry
sxtpypath = str(Path(__file__).parent.resolve())
if sxtpypath not in sys.path: sys.path.append(sxtpypath) 
from sxtenums import SXTApiCallTypes
from sxtexceptions import SxTArgumentError, SxTAPINotDefinedError
from sxtbiscuits import SXTBiscuit


class SXTBaseAPI():
    __au__:str = None 
    access_token = ''
    refresh_token = ''
    access_token_expires = 0
    refresh_token_expires = 0 
    logger: logging.Logger
    network_calls_enabled:bool = True
    standard_headers = {
                    "accept": "application/json",
                    "content-type": "application/json"
                    }
    versions = {}
    APICALLTYPE = SXTApiCallTypes


    def __init__(self, access_token:str = '', logger:logging.Logger = None) -> None:
        if logger: 
            self.logger = logger 
        else: 
            self.logger = logging.getLogger()
            self.logger.setLevel(logging.INFO)
            if len(self.logger.handlers) == 0: 
                self.logger.addHandler( logging.StreamHandler() )

        apiversionfile = Path(Path(__file__).resolve().parent / 'apiversions.json')
        self.access_token = access_token
        with open(apiversionfile,'r') as fh:
            content = fh.read()
        self.versions = json.loads(content)
        
    def __settokens__(self, accessToken:str, refreshToken:str, accessTokenExpires:int, refreshTokenExpires:int):
        self.access_token = accessToken
        self.refresh_token = refreshToken   
        self.access_token_expires = accessTokenExpires
        self.refresh_token_expires = refreshTokenExpires

    @property
    def api_url(self):
        return self.__au__ if self.__au__ else 'https://api.spaceandtime.dev' # default 
    @api_url.setter
    def api_url(self, value):
        self.__au__ = value
        
    def prep_biscuits(self, biscuits=[]) -> list:
        """--------------------
        Accepts biscuits in various data types, and returns a list of biscuit_tokens as strings (list of str).  
        Primary use-case is class-internal.

        Args: 
            biscuits (list | str | SXTBiscuit): biscuit_tokens as a list, str, or SXTBiscuit type. 

        Returns: 
            list: biscuit_tokens as a list.

        Examples:
            >>> sxt = SpaceAndTime()
            >>> biscuits = sxt.user.base_api.prep_biscuits(['a',['b','c'], 'd'])
            >>> biscuits == ['a', 'b', 'c', 'd']
            True
        """
        if   biscuits == None or len(biscuits) == 0:
            return [] 
        elif type(biscuits) == str:
            return [biscuits]
        elif 'SXTBiscuit' in str(type(biscuits)):  
            return [biscuits.biscuit_token]
        elif type(biscuits) == list:
            rtn=[]
            for biscuit in biscuits:
                rtn = rtn + self.prep_biscuits(biscuit)
            return rtn 
        else:
            self.logger.warning(f"""Biscuit provided was an unexpected type: {type(biscuits)}
                                Type must be one of [ str | list | SXTBiscuit object | None ]
                                Ingnoring this biscuit entry. Biscuit value provided:
                                {biscuits}""")
            return []


    def prep_sql(self, sql_text:str) -> str:
        """-------------------
        Cleans and prepares sql_text for transmission and execution on-network.

        Args: 
            sql_text (str): SQL text to prepare.

        Returns:
            sql: slightly modified / cleansed SQL text

        Examples:
            >>> api = SXTBaseAPI()
            >>> sql = "Select 'complex \nstring   ' as A \n   \t from \n\t TableName  \n Where    A=1;"
            >>> newsql = api.prep_sql(sql)
            >>> newsql == "Select 'complex \nstring   ' as A from TableName Where A=1"
            True
        """
        if sql_text == None or len(sql_text.strip()) == 0: return ''
        insinglequote = False
        indoublequote = False 
        rtn = []
        char = prevchar = ''
        for char in list(sql_text.strip()):

            # escape anything in quotes
            if   char == "'": insinglequote = not insinglequote
            elif char == '"': indoublequote = not indoublequote
            if insinglequote or indoublequote:
                rtn.append(char)
                prevchar = ''
                continue 

            # replace newlines and tabs with spaces
            if char in ['\n', '\t']: char = ' '
            
            # remove double-spaces
            if char == ' ' and prevchar == ' ': continue      

            rtn.append(char)
            prevchar = char

        # remove ; if last character
        if char == ';': rtn = rtn[:-1]
        return str(''.join(rtn)).strip()
            
    
    def call_api(self, endpoint: str, 
                 auth_header:bool = True, 
                 request_type:str = SXTApiCallTypes.POST, 
                 header_parms: dict = {}, 
                 data_parms: dict = {}, 
                 query_parms: dict = {}, 
                 path_parms: dict = {},
                 endpoint_full_override_flag: bool = False ) -> tuple[bool, object]:
        """--------------------
        Generic function to call and return SxT API. 

        This is the base api execution function.  It can, but is not intended, to be used directly.
        Rather, it is wrapped by other api-specific functions, to isolate api call differences
        from the actual api execution, which can all be the same. 

        Args:
            endpoint (str): URL endpoint, after the version. Final structure is: [api_url/version/endpoint] 
            request_type (SXTApiCallTypes): Type of request. [POST, GET, PUT, DELETE]
            auth_header (bool): flag indicator whether to append the Bearer token to the header. 
            header_parms: (dict): Name/Value pair to add to request header, except for bearer token. {Name: Value}
            query_parms: (dict): Name/value pairs to be added to the query string. {Name: Value}
            data_parms (dict): Dictionary to be used holistically for --data json object.
            path_parms (dict): Pattern to replace placeholders in URL. {Placeholder_in_URL: Replace_Value}
            endpoint_full_override_flag (str): If True, endpoint is used verbatium, rather than constructing version + endpoint. Will negate any querystring or path parms.

        Results:
            bool: Indicating request success
            json: Result of the API, expressed as a JSON object 
        """
        # Set these early, in case of timeout and they're not set by callfunc 
        txt = 'response.text not available - are you sure you have the correct API Endpoint?' 
        statuscode = 555
        response = {}

        # if network calls turned off, return fake data
        if not self.network_calls_enabled: return True, self.__fakedata__(endpoint)

        # internal function to simplify and unify error handling
        def __handle_errors__(txt, ex, statuscode, responseobject, loggerobject):
            loggerobject.error(txt)
            rtn = {'text':txt}
            rtn['error'] = str(ex)
            rtn['status_code'] = statuscode 
            rtn['response_object'] = responseobject
            return False, rtn

        # otherwise, go get real data
        try:
            # Header parms
            headers = {k:v for k,v in self.standard_headers.items()} # get new object
            if auth_header: headers['authorization'] = f'Bearer {self.access_token}'
            headers.update(header_parms)


            if endpoint_full_override_flag:
                url = endpoint
                self.logger.debug(f'API Call started for (custom) endpoint: {endpoint}')

            else:
                if endpoint not in self.versions.keys() and not endpoint_full_override_flag: 
                    raise SxTAPINotDefinedError("Endpoint not defined in API Lookup (apiversions.json). Please reach out to Space and Time for assistance. \nAs a work-around, you can try manually adding the endpoint to the SXTBaseAPI.versions dictionary.")
                version = self.versions[endpoint]
                self.logger.debug(f'API Call started for endpoint: {version}/{endpoint}')
            
                # Path parms
                for name, value in path_parms.items():
                    endpoint = endpoint.replace(f'{{{name}}}', value)
                
                # Query parms
                if query_parms !={}: 
                    endpoint = f'{endpoint}?' + '&'.join([f'{n}={v}' for n,v in query_parms.items()])

                # final URL
                url = f'{self.api_url}/{version}/{endpoint}'

            if request_type not in SXTApiCallTypes: 
                msg = f'request_type must be of type SXTApiCallTypes, not { type(request_type) }'
                raise SxTArgumentError(msg, logger=self.logger)
            
            # Call API function as defined above
            from pprint import pprint
            self.logger.debug(f'\nNew API call for endpoint: {url}')
            self.logger.debug('  headers:')
            self.logger.debug( headers if self.access_token=='' else str(headers).replace(self.access_token,'<<access_token>>') )
            self.logger.debug('  data parms:')
            self.logger.debug( data_parms if self.access_token=='' else str(data_parms).replace(self.access_token,'<<access_token>>') )
            match request_type:
                case SXTApiCallTypes.POST   : response = requests.post(url=url, data=json.dumps(data_parms), headers=headers)
                case SXTApiCallTypes.GET    : response = requests.get(url=url, data=json.dumps(data_parms), headers=headers)
                case SXTApiCallTypes.PUT    : response = requests.put(url=url, data=json.dumps(data_parms), headers=headers)
                case SXTApiCallTypes.DELETE : response = requests.delete(url=url, data=json.dumps(data_parms), headers=headers)

            txt = response.text
            statuscode = response.status_code
            response.raise_for_status()

            try:
                self.logger.debug('API return content type: ' + response.headers.get('content-type','') )
                rtn = response.json()
            except json.decoder.JSONDecodeError as ex:
                rtn = {'text':txt, 'status_code':statuscode}

            self.logger.debug( f'API call completed for endpoint: "{endpoint}" with result: {txt[:2000]}')
            return True, rtn

        except requests.exceptions.RequestException as ex:
            return __handle_errors__(txt, ex, statuscode, response, self.logger)
        except SxTAPINotDefinedError as ex:
            return __handle_errors__(txt, ex, statuscode, response, self.logger)
        except Exception as ex:
            return __handle_errors__(txt, ex, statuscode, response, self.logger)        
        

    def __fakedata__(self, endpoint:str):
        if endpoint in ['sql','sql/dql']:
            rtn = [{'id':'1', 'str':'a','this_record':'is a test'}]
            rtn.append( {'id':'2', 'str':'b','this_record':'is a test'} )
            rtn.append( {'id':'3', 'str':'c','this_record':'is a test'} )
            return rtn
        else:
            return {'authCode':'469867d9660b67f8aa12b2'
                        ,'accessToken':'eyJ0eXBlIjoiYWNjZXNzIiwia2lkIjUxNDVkYmQtZGNmYi00ZjI4LTg3NzItZjVmNjNlMzcwM2JlIiwiYWxnIjoiRVMyNTYifQ.eyJpYXQiOjE2OTczOTM1MDIsIm5iZiI6MTY5NzM5MzUwMiwiZXhwIjoxNjk3Mzk1MDAyLCJ0eXBlIjoiYWNjZXNzIiwidXNlciI6InN0ZXBoZW4iLCJzdWJzY3JpcHRpb24iOiIzMWNiMGI0Yi0xMjZlLTRlM2MtYTdhMS1lNWRmNDc4YTBjMDUiLCJzZXNzaW9uIjoiMzNiNGRhMzYxZjZiNTM3MjZlYmYyNzU4Iiwic3NuX2V4cCI6MTY5NzQ3OTkwMjMxNSwiaXRlcmF0aW9uIjoiNDEwY2YyZTgyYWZlODdmNDRiMzE4NDFiIn0.kpvrG-ro13P1YeMF6sjLh8wn1rO3jpCVeTrzhDe16ZmJu4ik1amcYz9uQff_XQcwBDrpnCeD5ZZ9mHqb_basew'
                        ,'refreshToken':'eyJ0eXBlIjoicmVmcmVzaCIsImtpZCITQ1ZGJkLWRjZmItNGYyOC04NzcyLWY1ZjYzZTM3MDNiZSIsImFsZyI6IkVTMjU2In0.eyJpYXQiOjE2OTczOTM1MDIsIm5iZiI6MTY5NzM5MzUwMiwiZXhwIjoxNjk3Mzk1MzAyLCJ0eXBlIjoicmVmcmVzaCIsInVzZXIiOiJzdGVwaGVuIiwic3Vic2NyaXB0aW9uIjoiMzFjYjBiNGItMTI2ZS00ZTNjLWE3YTEtZTVkZjQ3OGEwYzA1Iiwic2Vzc2lvbiI6IjMzYjRkYTM2MWY2YjUzNzI2ZWJmMjc1OCIsInNzbl9leHAiOjE2OTc0Nzk5MDIzMTUsIml0ZXJhdGlvbiI6IjQxMGNmMmU4MmFmZTg3ZjQ0YjMxODQxYiJ9.3vVYpTGBjXIejlaacaZOh_59O9ETfbvTCWvldoi0ojyXTRkTmENVpQRbw7av7yMM2jA7SRdEPQGGjYmThCfk9w'
                        ,'accessTokenExpires':1973950023160
                        ,'refreshTokenExpires':1973953023160
                        }


    def get_auth_challenge_token(self, user_id:str, prefix:str = None, joincode:str = None):
        """--------------------
        (alias) Calls and returns data from API: auth/code, which issues a random challenge token to be signed as part of the authentication workflow.
        
        Args: 
            user_id (str): UserID to be authenticated
            prefix (str): (optional) The message prefix for signature verification (used for improved front-end UX).
            joincode (str): (optional) Joincode if creating a new user within an existing subscription. 

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        return self.auth_code(user_id, prefix, joincode)
    

    def auth_code(self, user_id:str, prefix:str = None, joincode:str = None) -> tuple[bool, object]:
        """--------------------
        Calls and returns data from API: auth/code, which issues a random challenge token to be signed as part of the authentication workflow.
        
        Args: 
            user_id (str): UserID to be authenticated
            prefix (str): (optional) The message prefix for signature verification (used for improved front-end UX).
            joincode (str): (optional) Joincode if creating a new user within an existing subscription. 

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        dataparms = {"userId": user_id}
        if prefix: dataparms["prefix"] = prefix
        if joincode: 
            success, rtn = self.auth_code_register(user_id, prefix, joincode)
        else:
            success, rtn = self.call_api(endpoint = 'auth/code', auth_header = False, data_parms = dataparms)
        return success, rtn if success else [rtn]


    def gateway_proxy_add_existing_user(self, access_token:str) -> tuple[bool, object]:
        """-------------------- 
        Adds an authenticated user to the gateway proxy.  Fails if the user is not authenticated.

        Args: 
            user_id (str): UserID to be authenticated

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            dict: New Studio Password, or error message in a dict(json).
        """        
        endpoint = f'https://proxy.api.spaceandtime.dev/auth/add-existing?accessToken={access_token}'
        success, response = self.call_api(endpoint = endpoint, 
                                          auth_header = False, 
                                          endpoint_full_override_flag=True)
        self.logger.warning(f'add_user_to_gateway_proxy: {response}')
        if success and 'tempPassword' in response: response = response['tempPassword']
        return success, response



    def gateway_proxy_login (self, user_id:str, password:str) -> tuple[bool, object]:
        """-------------------- 
        Login to the gateway proxy, and return the session id.

        Args: 
            user_id (str): UserID to be authenticated
            password (str): Current, working password

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Gateway Proxy, including the session id, access token, etc.
        """        
        endpoint = 'https://proxy.api.spaceandtime.dev/auth/login'
        success, response = self.call_api(endpoint = endpoint, 
                                          auth_header = False, 
                                          data_parms = {"userId": user_id, "password": password},
                                          endpoint_full_override_flag=True)
        return success, response



    def gateway_proxy_change_password(self, user_id:str, old_password:str, new_password:str, session_id:str = None) -> tuple[bool, object]:
        """-------------------- 
        Logs into the gateway proxy and changes the user's password. Assuming the old_password still works, does not require network authentication.

        Args: 
            user_id (str): UserID to be authenticated
            old_password (str): Current, working password
            new_password (str): New password
            session_id (str): (optional) Session ID if already authenticated, otherwise this function will login and return authentication information as well.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Gateway Proxy, as list or dict(json). 
        """        
        endpoint = 'https://proxy.api.spaceandtime.dev/auth/reset'
        if not session_id:
            success, login_response = self.gateway_proxy_login(user_id, old_password)
            if not success: 
                raise SxTArgumentError(f'Failed to log into gateway proxy: {login_response}')
            session_id = login_response['sessionId']
 
        success, response = self.call_api(endpoint = endpoint, 
                                          auth_header = False, 
                                          header_parms={"sid": session_id},
                                          data_parms = {"userId": user_id, "sid": session_id, 
                                                        "tempPassword": old_password, "newPassword": new_password},
                                          endpoint_full_override_flag=True)
        self.logger.warning(f'changed gateway proxy password: {response}')
        if login_response: response.update(login_response)
        response['password'] = new_password
        return success, response


    def gateway_proxy_auth_apikey(self, api_key:str) -> tuple[bool, object]:
        """-------------------- 
        Logs into the gateway proxy using an API Key and returns an access token.

        Args: 
            api_key (str): API Key

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Gateway Proxy, as list or dict(json). 
        """     
        endpoint = 'https://proxy.api.spaceandtime.dev/auth/apikey'
        if not api_key: raise SxTArgumentError('api_key is required')
        success, response = self.call_api(endpoint = endpoint, 
                                          auth_header = False, 
                                          header_parms = {"apikey": api_key},
                                          endpoint_full_override_flag=True)
        if success: 
            self.__settokens__(response['accessToken'], response['refreshToken'], response['accessTokenExpires'], response['refreshTokenExpires'])
        return success, response
    

    def auth_apikey(self, api_key:str) -> tuple[bool, object]:
        """-------------------- 
        Logs into the gateway proxy using an API Key and returns an access token. This is an alias for gateway_proxy_auth_apikey().

        Args: 
            api_key (str): API Key

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Gateway Proxy, as list or dict(json). 
        """     
        return self.gateway_proxy_auth_apikey(api_key)
     


    def auth_code_register(self, user_id:str, email:str, joincode:str = None, prefix:str = None) -> tuple[bool, object]:
        """--------------------
        Calls and returns data from API: auth/code-register, which issues a random challenge token to be signed as part of the authentication workflow, but also requires additional information with which to register a new user on the network.
        
        Args: 
            user_id (str): UserID to be authenticated
            email (str): Email address to validate new user
            joincode (str): (optional) Joincode if creating a new user within an existing subscription. 
            prefix (str): (optional) The message prefix for signature verification (used for improved front-end UX).

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        dataparms = {"userId": user_id, "email": email}
        if prefix: dataparms["joincode"] = joincode
        if prefix: dataparms["prefix"] = prefix

        success, rtn = self.call_api(endpoint = 'auth/code-register', auth_header = False, data_parms = dataparms)
        return success, rtn if success else [rtn]


    def get_access_token(self, user_id:str, challange_token:str, signed_challange_token:str='', public_key:str=None, keymanager:object=None, scheme:str = "ed25519"):
        """--------------------
        (alias) Calls and returns data from API: auth/token, which validates signed challenge token and provides new Access_Token and Refresh_Token. 
        Can optionally supply a keymanager object, instead of the public_key and signed_challenge_token.        
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        return self.auth_token(user_id, challange_token, signed_challange_token, public_key, keymanager, scheme)


    def auth_token(self, user_id:str, challange_token:str, signed_challange_token:str='', public_key:str=None, keymanager:object=None, scheme:str = "ed25519"):
        """--------------------
        Calls and returns data from API: auth/token, which validates signed challenge token and provides new Access_Token and Refresh_Token. 
        Can optionally supply a keymanager object, instead of the public_key and signed_challenge_token. 
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        if keymanager: 
            try:
                public_key = keymanager.public_key_to(keymanager.ENCODINGS.BASE64)
                signed_challange_token = keymanager.sign_message(challange_token)
            except Exception as ex:
                return False, {'error':'keymanager object must be of type SXTKeyManager, if supplied.'}

        dataparms = { "userId": user_id
                     ,"signature": signed_challange_token
                     ,"authCode": challange_token
                     ,"key": public_key 
                     ,"scheme": scheme}
        success, rtn = self.call_api(endpoint='auth/token', auth_header=False, data_parms=dataparms)
        if success:
            self.__settokens__(rtn['accessToken'], rtn['refreshToken'], rtn['accessTokenExpires'], rtn['refreshTokenExpires'])
        return success, rtn if success else [rtn]


    def token_refresh(self, refresh_token:str):
        """--------------------
        Calls and returns data from API: auth/refresh, which accepts a Refresh_Token and provides a new Access_Token and Refresh_Token.        
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        headers = { 'authorization': f'Bearer {refresh_token}' }
        success, rtn = self.call_api('auth/refresh', False, header_parms=headers)
        if success:
            self.__settokens__(rtn['accessToken'], rtn['refreshToken'], rtn['accessTokenExpires'], rtn['refreshTokenExpires'])
        return success, rtn if success else [rtn]


    def auth_logout(self):
        """--------------------
        Calls and returns data from API: auth/logout, which invalidates Access_Token and Refresh_Token.        
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        success, rtn = self.call_api('auth/logout', True)
        return success, rtn if success else [rtn]


    def auth_validtoken(self):
        """--------------------
        Calls and returns data from API: auth/validtoken, which returns information on a valid token.        
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        success, rtn = self.call_api('auth/validtoken', True, SXTApiCallTypes.GET)
        return success, rtn if success else [rtn]
    

    def auth_idexists(self, user_id:str ):
        """--------------------
        Calls and returns data from API: auth/idexists, which returns True if the User_ID supplied exists, False if not.        
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        success, rtn = self.call_api('auth/idexists/{id}', False, SXTApiCallTypes.GET, path_parms={'id':user_id})
        return success, rtn if success else [rtn]
    
    
    def auth_keys(self):
        """--------------------
        Calls and returns data from API: auth/keys (get), which returns all keys for a valid token.        
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        success, rtn = self.call_api('auth/keys', True, SXTApiCallTypes.GET)
        return success, rtn if success else [rtn]


    def auth_addkey(self, user_id:str, public_key:str, challange_token:str, signed_challange_token:str, scheme:str = "ed25519"):
        """--------------------
        Calls and returns data from API: auth/keys (post), which adds a new key to the valid token. Requires similar challenge/sign/return as authentication.        
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        dataparms = { "authCode": challange_token
                    ,"signature": signed_challange_token
                    ,"key": public_key
                    ,"scheme": scheme }
        success, rtn = self.call_api('auth/keys', True, SXTApiCallTypes.POST, data_parms=dataparms)
        return success, rtn if success else [rtn]


    def auth_addkey_challenge(self):
        """--------------------
        Request a challenge token from the Space and Time network, for authentication.

        (alias) Calls and returns data from API: auth/keys (get), which returns all keys for a valid token.        
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        return self.auth_keys_code()
    

    def auth_keys_code(self):
        """--------------------
        Calls and returns data from API: auth/keys (get), which returns all keys for a valid token.        
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        success, rtn = self.call_api('auth/keys/code', True)
        return success, rtn if success else [rtn]
    

    def sql_exec(self, sql_text:str, biscuits:list = None, app_name:str = None, validate:bool = False):
        """--------------------
        Executes a database statement/query of arbitrary type (DML, DDL, DQL), and returns a status or data.

        Calls and returns data from API: sql, which runs arbitrary SQL and returns records (if any).
        This api call undergoes one additional SQL parse step to interrogate the type and 
        affected tables / views, so is slightly less performant (by 50-100ms) than the type-specific 
        api calls, sql_ddl, sql_dml, sql_dql.  Normal human interaction will not be noticed, but
        if tuning for high-performance applications, consider using the correct typed call.

        Args:        
            sql_text (str): SQL query text to execute. Note, there is NO placeholder replacement.
            biscuits (list): (optional) List of biscuit tokens for permissioned tables. If only querying public tables, this is not needed.
            app_name (str): (optional) Name that will appear in querylog, used for bucketing workload.
            validate (bool): (optional) Perform an additional SQL validation in-parser, before database submission.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        headers = { 'originApp': app_name } if app_name else {}
        sql_text = self.prep_sql(sql_text=sql_text)
        biscuit_tokens = self.prep_biscuits(biscuits)
        if type(biscuit_tokens) != list:  raise SxTArgumentError("sql_all requires parameter 'biscuits' to be a list of biscuit_tokens or SXTBiscuit objects.",  logger = self.logger)
        dataparms = {"sqlText": sql_text
                    ,"biscuits": biscuit_tokens
                    ,"validate": str(validate).lower() }
        success, rtn = self.call_api('sql', True, header_parms=headers, data_parms=dataparms)
        return success, rtn if success else [rtn]


    def sql_ddl(self, sql_text:str, biscuits:list = None, app_name:str = None):
        """--------------------
        **deprecated** -- now simply calls sql_exec. 

        Args: 
            sql_text (str): SQL query text to execute. Note, there is NO placeholder replacement.
            biscuits (list): (optional) List of biscuit tokens for permissioned tables. If only querying public tables, this is not needed.
            app_name (str): (optional) Name that will appear in querylog, used for bucketing workload.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        return self.sql_exec(sql_text=sql_text, biscuits=biscuits, app_name=app_name)


    def sql_dml(self, sql_text:str, resources:list, biscuits:list = None, app_name:str = None):
        """--------------------
        **deprecated** -- now simply calls sql_exec. 

        Args: 
            sql_text (str): SQL query text to execute. Note, there is NO placeholder replacement.
            resources (list): ** ignored / unneeded **
            biscuits (list): (optional) List of biscuit tokens for permissioned tables. If only querying public tables, this is not needed.
            app_name (str): (optional) Name that will appear in querylog, used for bucketing workload.
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        return self.sql_exec(sql_text=sql_text, biscuits=biscuits, app_name=app_name)


    def sql_dql(self, sql_text:str, resources:list, biscuits:list = None, app_name:str = None):
        """--------------------
        **deprecated** -- now simply calls sql_exec. 

        Args: 
            sql_text (str): SQL query text to execute. Note, there is NO placeholder replacement.
            resources (list): ** ignored / unneeded **
            biscuits (list): (optional) List of biscuit tokens for permissioned tables. If only querying public tables, this is not needed.
            app_name (str): (optional) Name that will appear in querylog, used for bucketing workload.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        return self.sql_exec(sql_text=sql_text, biscuits=biscuits, app_name=app_name)


    def sql_exec_tamperproof(self, sql_text:str, biscuits:list = None):
        """--------------------
        Executes a ZK tamperproof database statement/query, and returns a status or data plus a ZK verification code.

        Args:        
            sql_text (str): SQL query text to execute. Note, there is NO placeholder replacement.
            biscuits (list): (optional) List of biscuit tokens for permissioned tables. If only querying public tables, this is not needed.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        sql_text = self.prep_sql(sql_text=sql_text)
        biscuit_tokens = self.prep_biscuits(biscuits)
        if type(biscuit_tokens) != list:  raise SxTArgumentError("sql_all requires parameter 'biscuits' to be a list of biscuit_tokens or SXTBiscuit objects.",  logger = self.logger)
        dataparms = {"sqlText": sql_text
                    ,"biscuits": biscuit_tokens }
        success, rtn = self.call_api('sql/tamperproof-query', True, data_parms=dataparms)
        return success, rtn if success else [rtn]


    def discovery_get_schemas(self, scope:str = 'ALL'):
        """--------------------
        Connects to the Space and Time network and returns all available schemas.
        
        Calls and returns data from API: discover/schema 

        Args:
            scope (SXTDiscoveryScope): (optional) Scope of objects to return: All, Public, Subscription, or Private. Defaults to SXTDiscoveryScope.ALL.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list of dict. 
        """
        success, rtn = self.call_api('discover/schema',True, SXTApiCallTypes.GET, query_parms={'scope':scope})
        return success, (rtn if success else [rtn]) 
        

    def discovery_get_tables(self, schema:str = 'ETHEREUM', scope:str = 'ALL', search_pattern:str = None):
        """--------------------
        Connects to the Space and Time network and returns all available tables within a schema.

        Calls and returns data from API: discover/table         
        
        Args:
            schema (str): Schema name to search for tables.
            scope (SXTDiscoveryScope): (optional) Scope of objects to return: All, Public, Subscription, or Private. Defaults to SXTDiscoveryScope.ALL.
            search_pattern (str): (optional) Tablename pattern to match for inclusion into result set. Defaults to None / all tables.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list of dict. 
        """
        allowed_scope = ['subscription', 'public', 'all']
        if scope.lower() not in allowed_scope:
            raise SxTArgumentError(f"Invalid value for scope '{scope}'. Must be one of {allowed_scope}.", logger = self.logger)
        version = 'v2' if 'discover/table' not in list(self.versions.keys()) else self.versions['discover/table'] 
        schema_or_namespace = 'namespace' if version=='v1' else 'schema'
        query_parms = {schema_or_namespace:schema.upper()}
        if version != 'v1' and search_pattern: query_parms['searchPattern'] = search_pattern
        
        all_tables = []
        success = True
        for current_scope in ['subscription', 'public']:
            if scope.lower() in [current_scope, 'all']:
                query_parms['scope'] = current_scope    
                partial_success, rtn = self.call_api('discover/table',True,  SXTApiCallTypes.GET, query_parms=query_parms)
                if not partial_success: success = False
                if all_tables == []: # dedup a list of dicts, based on the table name
                    all_tables = rtn
                else: 
                    for r in rtn: 
                        if r['table'] not in [r['table'] for r in all_tables]: all_tables.append(r)
        return success, (all_tables if success else [all_tables]) 


    def discovery_get_views(self, schema:str = 'ETHEREUM', scope:str = 'ALL', search_pattern:str = None):
        """--------------------
        Connects to the Space and Time network and returns all available tables within a schema.

        Calls and returns data from API: discover/table         
        
        Args:
            schema (str): Schema name to search for tables.
            scope (SXTDiscoveryScope): (optional) Scope of objects to return: All, Public, Subscription, or Private. Defaults to SXTDiscoveryScope.ALL.
            search_pattern (str): (optional) Tablename pattern to match for inclusion into result set. Defaults to None / all tables.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list of dict. 
        """
        version = 'v2' if 'discover/view' not in list(self.versions.keys()) else self.versions['discover/view'] 
        query_parms = {'scope':scope.upper(), 'schema':schema.upper()}
        if version != 'v1' and search_pattern: query_parms['searchPattern'] = search_pattern
        success, rtn = self.call_api('discover/view',True,  SXTApiCallTypes.GET, query_parms=query_parms)
        return success, (rtn if success else [rtn]) 


    def discovery_get_columns(self, schema:str, table:str):
        """--------------------
        Connects to the Space and Time network and returns all available columns within a table.

        Calls and returns data from API: discover/table         
        
        Args:
            schema (str): Schema name for which to retrieve tables.
            table (str): Table name for which to retrieve columns.  This should be tablename only, NOT schema.tablename.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list of dict. 
        """
        version = 'v2' if 'discover/table/column' not in list(self.versions.keys()) else self.versions['discover/table/column'] 
        schema_or_namespace = 'namespace' if version=='v1' else 'schema'
        query_parms = {schema_or_namespace:schema.upper(), 'table':table}
        success, rtn = self.call_api('discover/table/column',True,  SXTApiCallTypes.GET, query_parms=query_parms)
        return success, (rtn if success else [rtn]) 
    


    def subscription_set_name(self, name:str) -> tuple[bool, dict]:
        """--------------------
        Assigns a user-friendly name to an existing subscription.
        
        Args: 
            name (str): Subscription user-friendly name.  

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        if len(name)==0: return False, 'Name cannot be empty.'
        success, rtn = self.call_api('subscription/name', True, SXTApiCallTypes.PUT, query_parms={'subscriptionName':name})
        return success, {n:v for n,v in rtn.items() if v} if success else rtn


    def subscription_get_info(self):
        """--------------------
        Retrieves information on the authenticated user's subscription from the Space and Time network.

        Calls and returns data from API: subscription         
        
        Args: 
            None 

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        endpoint = 'subscription'
        version = 'v2' if endpoint not in list(self.versions.keys()) else self.versions[endpoint] 
        success, rtn = self.call_api(endpoint=endpoint, auth_header=True, request_type=SXTApiCallTypes.GET )
        return success, (rtn if success else [rtn]) 
     

    def subscription_get_users(self):
        """--------------------
        Retrieves information on all users of a subscription from the Space and Time network.  May be restricted to Admin or Owners.

        Calls and returns data from API: subscription/users         
        
        Args:
            None

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        endpoint = 'subscription/users'
        version = 'v2' if endpoint not in list(self.versions.keys()) else self.versions[endpoint] 
        success, rtn = self.call_api(endpoint=endpoint, auth_header=True, request_type=SXTApiCallTypes.GET )
        return success, (rtn if success else [rtn]) 
    

    def subscription_invite_user(self, role:str = 'member'):
        """--------------------
        Creates a subcription invite code (aka joincode).  Can join as member, admin, owner.

        Calls and returns data from API: subscription/invite.  
        Allows an Admin or Owner to generate a joincode for another user, who (after authenticating) 
        can consume the code and join the subcription at the specified level. 
        The code is only valid for 24 hours, and assigned role cannot be greater than the creator
        (i.e., an Admin cannot generate an Owner code).

        Args: 
            role (str): Role level to assign the new user. Can be member, admin, or owner.
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        endpoint = 'subscription/invite'
        role = role.upper().strip()
        if role not in ['MEMBER','ADMIN','OWNER']:
            return False, {'error':'Invites must be either member, admin, or owner.  Permissions cannot exceed the invitor.'}
        version = 'v2' if endpoint not in list(self.versions.keys()) else self.versions[endpoint] 
        success, rtn = self.call_api(endpoint=endpoint, auth_header=True, request_type=SXTApiCallTypes.POST,
                                     query_parms={'role':role} )
        return success, (rtn if success else [rtn]) 


    def subscription_join(self, joincode:str):
        """--------------------
        Allows the authenticated user to join a subscription by using a valid joincode.

        Calls and returns data from API: subscription/invite/{joinCode}.  
        Note, joincodes are only valid for 24 hours.

        Args: 
            joincode (str): Code created by an admin to allow an authenticated user to join their subscription.
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        endpoint = 'subscription/invite/{joinCode}'
        version = 'v2' if endpoint not in list(self.versions.keys()) else self.versions[endpoint] 
        success, rtn = self.call_api(endpoint=endpoint, auth_header=True, request_type=SXTApiCallTypes.POST,
                                     path_parms= {'joinCode': joincode} )
        return success, (rtn if success else [rtn]) 


    def subscription_leave(self):
        """--------------------
        Allows the authenticated user to leave their subscription.

        Calls and returns data from API: subscription/leave.  

        Args: 
            None
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        endpoint = 'subscription/leave'
        version = 'v2' if endpoint not in list(self.versions.keys()) else self.versions[endpoint] 
        success, rtn = self.call_api(endpoint=endpoint, auth_header=True, request_type=SXTApiCallTypes.POST )
        return success, (rtn if success else [rtn])


    def subscription_get_users(self) -> tuple[bool, dict]:
        """
        Returns a list of all users in the current subscription.

        Args:
            None

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Dictionary of User_IDs and User Permission level in the subscription, or error as json.
        """
        endpoint = 'subscription/users'
        version = 'v2' if endpoint not in list(self.versions.keys()) else self.versions[endpoint] 
        success, rtn = self.call_api(endpoint=endpoint, auth_header=True, request_type=SXTApiCallTypes.GET )
        if success: rtn = rtn['roleMap']
        return success, rtn
        

    def subscription_remove(self, User_ID_to_Remove:str) -> tuple[bool, dict]:
        """
        Removes another user from the current user's subscription.  Current user must have more authority than the targeted user to remove.

        Args: 
            User_ID_to_Remove (str): ID of the user to remove from the current user's subscription.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json).
        """
        endpoint = 'subscription/remove/{userId}'
        version = 'v2' if endpoint not in list(self.versions.keys()) else self.versions[endpoint] 
        success, rtn = self.call_api(endpoint=endpoint, auth_header=True, request_type=SXTApiCallTypes.POST,
                                     path_parms= {'userId': User_ID_to_Remove} )
        return success, rtn
        

 