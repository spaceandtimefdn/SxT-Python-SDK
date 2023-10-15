import requests, logging, json
from pathlib import Path
from sxtenums import SXTApiCallTypes
from sxtexceptions import SxTArgumentError
from sxtbiscuits import SXTBiscuit


class SXTBaseAPI():
    api_url = 'https://api.spaceandtime.app'
    access_token = ''
    logger: logging.Logger
    network_calls_enabled:bool = True
    standard_headers = {
                    "accept": "application/json",
                    "content-type": "application/json"
                    }
    versions = {}


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


    def prep_biscuits(self, biscuits=list) -> list:
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
        if   type(biscuits) == str:
            return [biscuits]
        elif type(biscuits) == SXTBiscuit:  
            return [biscuits.biscuit_token]
        elif type(biscuits) == list:
            rtn=[]
            for biscuit in biscuits:
                rtn = rtn + self.prep_biscuits(biscuit)
            return rtn 
        else:
            return None


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
        insinglequote = False
        indoublequote = False 
        rtn = []
        prevchar = ''
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
                 path_parms: dict = {} ):
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

        Results:
            bool: Indicating request success
            json: Result of the API, expressed as a JSON object 
        """
        try:
            version = self.versions[endpoint]
            self.logger.debug(f'API Call started for endpoint: {version}/{endpoint}')

            if request_type not in SXTApiCallTypes: 
                msg = f'request_type must be of type SXTApiCallTypes, not { type(request_type) }'
                raise SxTArgumentError(msg, logger=self.logger)
           
            # Path parms
            for name, value in path_parms.items():
                endpoint = endpoint.replace(name,value)
            
            # Query parms
            if query_parms !={}: 
                endpoint = f'{endpoint}?' + '&'.join([f'{n}={v}' for n,v in query_parms.items()])
            
            # Header parms
            headers = {k:v for k,v in self.standard_headers.items()}
            if auth_header: headers['authorization'] = f'Bearer {self.access_token}'
            headers.update(header_parms)

            # final URL
            url = f'{self.api_url}/{version}/{endpoint}'

            match request_type:
                case SXTApiCallTypes.POST   : callfunc = requests.post
                case SXTApiCallTypes.GET    : callfunc = requests.get
                case SXTApiCallTypes.PUT    : callfunc = requests.put
                case SXTApiCallTypes.DELETE : callfunc = requests.delete
                case _: raise SxTArgumentError('Call type must be SXTApiCallTypes enum.', logger=self.logger)

            if self.network_calls_enabled:
                response = callfunc(url=url, data=json.dumps(data_parms), headers=headers)
            else:
                if endpoint in ['sql','sql/dql']:
                    rtn = [{'id':'1', 'str':'a','this_record':'is a test'}]
                    rtn.append( {'id':'2', 'str':'b','this_record':'is a test'} )
                    rtn.append( {'id':'3', 'str':'c','this_record':'is a test'} )
                    return True, rtn
                else:
                    return True, {'authCode':'469867d9660b67f8aa12b2'
                                ,'accessToken':'eyJ0eXBlIjoiYWNjZXNzIiwia2lkIjUxNDVkYmQtZGNmYi00ZjI4LTg3NzItZjVmNjNlMzcwM2JlIiwiYWxnIjoiRVMyNTYifQ.eyJpYXQiOjE2OTczOTM1MDIsIm5iZiI6MTY5NzM5MzUwMiwiZXhwIjoxNjk3Mzk1MDAyLCJ0eXBlIjoiYWNjZXNzIiwidXNlciI6InN0ZXBoZW4iLCJzdWJzY3JpcHRpb24iOiIzMWNiMGI0Yi0xMjZlLTRlM2MtYTdhMS1lNWRmNDc4YTBjMDUiLCJzZXNzaW9uIjoiMzNiNGRhMzYxZjZiNTM3MjZlYmYyNzU4Iiwic3NuX2V4cCI6MTY5NzQ3OTkwMjMxNSwiaXRlcmF0aW9uIjoiNDEwY2YyZTgyYWZlODdmNDRiMzE4NDFiIn0.kpvrG-ro13P1YeMF6sjLh8wn1rO3jpCVeTrzhDe16ZmJu4ik1amcYz9uQff_XQcwBDrpnCeD5ZZ9mHqb_basew'
                                ,'refreshToken':'eyJ0eXBlIjoicmVmcmVzaCIsImtpZCITQ1ZGJkLWRjZmItNGYyOC04NzcyLWY1ZjYzZTM3MDNiZSIsImFsZyI6IkVTMjU2In0.eyJpYXQiOjE2OTczOTM1MDIsIm5iZiI6MTY5NzM5MzUwMiwiZXhwIjoxNjk3Mzk1MzAyLCJ0eXBlIjoicmVmcmVzaCIsInVzZXIiOiJzdGVwaGVuIiwic3Vic2NyaXB0aW9uIjoiMzFjYjBiNGItMTI2ZS00ZTNjLWE3YTEtZTVkZjQ3OGEwYzA1Iiwic2Vzc2lvbiI6IjMzYjRkYTM2MWY2YjUzNzI2ZWJmMjc1OCIsInNzbl9leHAiOjE2OTc0Nzk5MDIzMTUsIml0ZXJhdGlvbiI6IjQxMGNmMmU4MmFmZTg3ZjQ0YjMxODQxYiJ9.3vVYpTGBjXIejlaacaZOh_59O9ETfbvTCWvldoi0ojyXTRkTmENVpQRbw7av7yMM2jA7SRdEPQGGjYmThCfk9w'
                                ,'accessTokenExpires':1973950023160
                                ,'refreshTokenExpires':1973953023160
                                }
            txt = 'response.text not available'
            txt = response.text
            response.raise_for_status()

            try:
                rtn = response.json()
            except json.decoder.JSONDecodeError as ex:
                rtn = {'status_code':response.status_code, 'text':txt}

            self.logger.debug(f'API call completed for endpoint: "{endpoint}" with result: {txt}')
            return True, rtn

        except requests.exceptions.RequestException as ex:
            self.logger.error(str(txt))
            return False, {'status':response.status_code, 'error': txt}
        except Exception as ex:
            self.logger.error(str(txt))
            return False, {'status':response.status_code, 'error': txt}


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
    

    def auth_code(self, user_id:str, prefix:str = None, joincode:str = None):
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
        if joincode: dataparms[joincode] = joincode
        success, rtn = self.call_api(endpoint = 'auth/code', auth_header = False, data_parms = dataparms)
        return success, rtn if success else [rtn]


    def get_access_token(self, user_id:str, public_key:str, challange_token:str, signed_challange_token:str, scheme:str = "ed25519"):
        """--------------------
        (alias) Calls and returns data from API: auth/token, which validates signed challenge token and provides new Access_Token and Refresh_Token.        
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        return self.auth_token(user_id, public_key, challange_token, signed_challange_token, scheme)


    def auth_token(self, user_id:str, public_key:str, challange_token:str, signed_challange_token:str, scheme:str = "ed25519"):
        """--------------------
        Calls and returns data from API: auth/token, which validates signed challenge token and provides new Access_Token and Refresh_Token.        
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        dataparms = { "userId": user_id
                     ,"signature": signed_challange_token
                     ,"authCode": challange_token
                     ,"key": public_key 
                     ,"scheme": scheme}
        success, rtn = self.call_api(endpoint='auth/token', auth_header=False, data_parms=dataparms)
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
        success, rtn = self.call_api(f'auth/idexists/{user_id}', False, SXTApiCallTypes.GET)
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
        if tuning for high-performnace applications, consider using the correct typed call.

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
        if type(biscuit_tokens) != list:  raise SxTArgumentError("sql_all requires parameter 'biscuits' to be a list of biscuit_tokens or SXTBiscuit objects.", logging= self.logging)
        dataparms = {"sqlText": sql_text
                    ,"biscuits": biscuit_tokens
                    ,"validate": str(validate).lower() }
        success, rtn = self.call_api('sql', True, header_parms=headers, data_parms=dataparms)
        return success, rtn if success else [rtn]


    def sql_ddl(self, sql_text:str, biscuits:list = None, app_name:str = None):
        """--------------------
        Executes a database DDL statement, and returns status.

        Calls and returns data from API: sql/ddl, which runs arbitrary DDL for creating resources.        
        This will be slightly more performant than the generic sql_exec function, but requires a resource name.
        Biscuits are always required for DDL.

        Args: 
            sql_text (str): SQL query text to execute. Note, there is NO placeholder replacement.
            biscuits (list): (optional) List of biscuit tokens for permissioned tables. If only querying public tables, this is not needed.
            app_name (str): (optional) Name that will appear in querylog, used for bucketing workload.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        headers = { 'originApp': app_name } if app_name else {}
        sql_text = self.prep_sql(sql_text=sql_text)
        biscuit_tokens = self.prep_biscuits(biscuits)
        if biscuit_tokens==[]:  raise SxTArgumentError("sql_all requires parameter 'biscuits' to be a single or list of string biscuit_tokens or SXTBiscuit objects.", logging= self.logging)
        dataparms = {"sqlText": sql_text
                    ,"biscuits": biscuit_tokens }
                    # ,"resources": [r for r in resources] }
        success, rtn = self.call_api('sql/ddl', True, header_parms=headers, data_parms=dataparms)
        return success, rtn if success else [rtn]


    def sql_dml(self, sql_text:str, resources:list, biscuits:list = None, app_name:str = None):
        """--------------------
        Executes a database DML statement, and returns status.

        Calls and returns data from API: sql/dml, which runs arbitrary DML for manipulating data. 
        This will be slightly more performant than the generic sql_exec function, but requires a resource name.
        Biscuits are required for any non-public-write tables.

        Args: 
            sql_text (str): SQL query text to execute. Note, there is NO placeholder replacement.
            resources (list): List of Resources ("schema.table_name") in the sql_text. 
            biscuits (list): (optional) List of biscuit tokens for permissioned tables. If only querying public tables, this is not needed.
            app_name (str): (optional) Name that will appear in querylog, used for bucketing workload.
        
        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        if type(resources) != list: resources = [resources]
        headers = { 'originApp': app_name } if app_name else {}
        sql_text = self.prep_sql(sql_text=sql_text)
        biscuit_tokens = self.prep_biscuits(biscuits)
        if type(biscuit_tokens) != list:  raise SxTArgumentError("sql_all requires parameter 'biscuits' to be a list of biscuit_tokens or SXTBiscuit objects.", logging= self.logging)
        headers = { 'originApp': app_name } if app_name else {}
        dataparms = {"sqlText": sql_text
                    ,"biscuits": biscuit_tokens
                    ,"resources": [r for r in resources] }
        success, rtn = self.call_api('sql/dml', True, header_parms=headers, data_parms=dataparms)
        return success, rtn if success else [rtn]


    def sql_dql(self, sql_text:str, resources:list, biscuits:list = None, app_name:str = None):
        """--------------------
        Executes a database DQL / SQL query, and returns a dataset as a list of dictionaries.

        Calls and returns data from API: sql/dql, which runs arbitrary SELECT statements that return data.        
        This will be slightly more performant than the generic sql_exec function, but requires a resource name.
        Biscuits are required for any non-public tables.

        Args: 
            sql_text (str): SQL query text to execute. Note, there is NO placeholder replacement.
            resources (list): List of Resources ("schema.table_name") in the sql_text. 
            biscuits (list): (optional) List of biscuit tokens for permissioned tables. If only querying public tables, this is not needed.
            app_name (str): (optional) Name that will appear in querylog, used for bucketing workload.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        if type(resources) != list: resources = [resources]
        headers = { 'originApp': app_name } if app_name else {}
        sql_text = self.prep_sql(sql_text=sql_text)
        biscuit_tokens = self.prep_biscuits(biscuits)
        if type(biscuit_tokens) != list:  raise SxTArgumentError("sql_all requires parameter 'biscuits' to be a list of biscuit_tokens or SXTBiscuit objects.", logging= self.logging)
        dataparms = {"sqlText": sql_text
                    ,"biscuits": biscuit_tokens
                    ,"resources": [r for r in resources] }
        success, rtn = self.call_api('sql/dql', True, header_parms=headers, data_parms=dataparms)
        return success, rtn if success else [rtn]


    def discovery_get_schemas(self, scope:str = 'ALL'):
        """--------------------
        Connects to the Space and Time network and returns all available schemas.
        
        Calls and returns data from API: discover/schema 

        Args:
            scope (SXTDiscoveryScope): (optional) Scope of objects to return: All, Public, Subscription, or Private. Defaults to SXTDiscoveryScope.ALL.

        Returns:
            bool: Success flag (True/False) indicating the api call worked as expected.
            object: Response information from the Space and Time network, as list or dict(json). 
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
            object: Response information from the Space and Time network, as list or dict(json). 
        """
        version = 'v2' if 'discover/table' not in list(self.versions.keys()) else self.versions['discover/table'] 
        schema_or_namespace = 'namespace' if version=='v1' else 'schema'
        query_parms = {'scope':scope.upper(), schema_or_namespace:schema.upper()}
        if version != 'v1' and search_pattern: query_parms['searchPattern'] = search_pattern
        success, rtn = self.call_api('discover/table',True,  SXTApiCallTypes.GET, query_parms=query_parms)
        return success, (rtn if success else [rtn]) 
     

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
                                     path_parms= {'{joinCode}': joincode} )
        return success, (rtn if success else [rtn]) 



if __name__ == '__main__':

    token = 'eyJ0eXBlIjoiYWNjZXNzIiwia2lkIjoiZTUxNDVkYmQtZGNmYi00ZjI4LTg3NzItZjVmNjNlMzcwM2JlIiwiYWxnIjoiRVMyNTYifQ.eyJpYXQiOjE2OTU5MTQxMjgsIm5iZiI6MTY5NTkxNDEyOCwiZXhwIjoxNjk1OTE1NjI4LCJ0eXBlIjoiYWNjZXNzIiwidXNlciI6InN0ZXBoZW4iLCJzdWJzY3JpcHRpb24iOiIzMWNiMGI0Yi0xMjZlLTRlM2MtYTdhMS1lNWRmNDc4YTBjMDUiLCJzZXNzaW9uIjoiNTg2OTQyOTgzMjc2OTkyNzI5MDViMDQyIiwic3NuX2V4cCI6MTY5NjAwMDUyODQ2OSwiaXRlcmF0aW9uIjoiZDc0M2Y1YjRkNTkyYzdmNjU4ZDA5ZmM2In0.lKjO0CbQ4k8hAEPsbs9nL1qXGzm01ZfJEF_l8NiRQRbTBkrdPV53H8lzdJsHTpGdcgSvsgbwpxzKvUnqyl1cAg'
    api = SXTBaseAPI(token)
    
    print( api.subscription_get_info() )
    success, users = api.subscription_get_users() 

    success, response = api.subscription_invite_user(role='owner')
    joincode = response['text']

    print( api.subscription_join(joincode=joincode) )

    pass 