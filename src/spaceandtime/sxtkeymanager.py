import logging, base64
from pathlib import Path 
import nacl.signing
from biscuit_auth import KeyPair, PrivateKey 
from .sxtexceptions import SxTKeyEncodingError
from .sxtenums import SXTKeyEncodings



####
#### SXT KEY MANAGER
####
class SXTKeyManager():
    """Class to manage creation and maintenance of keys and biscuits."""

    biscuits:list = []
    logger:logging.Logger = None
    warning_for_biscuit_length = 1800
    keychange_callback_func_list = []
    __pv:bytes = bytes(''.encode())
    __pb:bytes = bytes(''.encode())
    __en:SXTKeyEncodings = SXTKeyEncodings.BASE64
    ENCODINGS = SXTKeyEncodings


    def __init__(self, private_key:str = None, new_keypair: bool = False, encoding:SXTKeyEncodings = None, keychange_callback_func = None, logger:logging.Logger = None) -> None:
        """Class to manage creation and maintenance of keys and biscuits."""
        if logger: 
            self.logger = logger 
        else: 
            self.logger = logging.getLogger()
            self.logger.setLevel(logging.INFO)
            if len(self.logger.handlers) == 0: 
                self.logger.addHandler( logging.StreamHandler() )
        self.logger.info('new SXT KeyManager initiated')
        self.keychange_callback_func_list = []
        if keychange_callback_func: self.add_keychange_callback(keychange_callback_func)

        if encoding: self.encoding = encoding
        if new_keypair: 
            self.new_keypair()
            return None
        if private_key: self.private_key = private_key
        return None
    

    def __str__(self):
        flds = self.__keydict__()
        flds['private_key'] = flds['private_key'][:6]+'...'
        return '\n'.join( [ f'\t{n} = {v}' for n,v in flds.items() ] )
    
    def __repr__(self):
        return  '\n'.join( [ f'\t{n} = {v}' for n,v in self.__keydict__().items() ] )
    
    def __keydict__(self, keychanged:str = None) -> dict:
        rtn = {'private_key': self.private_key, 
                'public_key': self.public_key, 
                'encoding': self.encoding.name }
        if keychanged: rtn['key_changed'] = keychanged
        return rtn
    
    def __callback__(self, keychanged:str ) -> None:
        for func in self.keychange_callback_func_list:
            func( self.__keydict__(keychanged) )

    @property
    def private_key(self):
        return self.convert_key(self.__pv, SXTKeyEncodings.BYTES, self.encoding)
    @private_key.setter
    def private_key(self, value):
        self.__pv = self.convert_key(value, self.get_encoding_type(value), SXTKeyEncodings.BYTES) if value else ''
        self.__pb = ''
        self.__callback__('private_key')
        self.logger.debug(f'private key updated to { self.__pv[:6] }...')

    @property
    def public_key(self):
        if self.__pv and not self.__pb:
            kp = KeyPair.from_private_key(PrivateKey.from_hex( self.convert_key(self.__pv, encoding_out = SXTKeyEncodings.HEX)))
            self.__pb = bytes(kp.public_key.to_bytes())
            self.__callback__('public_key')
        return self.convert_key(self.__pb, encoding_out= self.encoding)
    @public_key.setter
    def public_key(self, value):
        self.__pb = self.convert_key(value, self.get_encoding_type(value), SXTKeyEncodings.BYTES) if value else ''
        self.__callback__('public_key')
        self.logger.debug(f'public key updated to { self.__pb }...')

    @property
    def encoding(self):
        return self.__en
    @encoding.setter
    def encoding(self, value) -> str:
        if not value in SXTKeyEncodings:
            raise SxTKeyEncodingError("Invalid encoding option, must be a member of SXTKeyEncodings", logger=self.logger)
        self.__en = value

    def private_key_to(self, encoding_out: SXTKeyEncodings = SXTKeyEncodings.HEX):
        return self.convert_key( key=self.__pv, encoding_out = encoding_out )
    
    def public_key_to(self, encoding_out: SXTKeyEncodings = SXTKeyEncodings.HEX):
        return self.convert_key( key=self.__pb, encoding_out = encoding_out )
    
    def get_encoding_type(self, key) -> str:
        """--------------------
        Accepts a key str or bytes, and returns the encoding type, [bytes, hex, base64].

        Args:
            key (any): Key to evaluate, as a string or bytes.

        Returns:
            str: Encoding type, [bytes, hex, base64]

        Examples:
            >>> SXTKeyManager().get_encoding_type("k6G2adpHxohA9sOBwHV8KRE5eDAJ/IEfocv5zkODgjA=")
            base64
            >>> SXTKeyManager().get_encoding_type("7063e65f0ba0e2aaaeb7d240248be19fea6f68dcccb50e0f2de3e22595f84751")
            hex
            >>> SXTKeyManager().get_encoding_type(b'\x93\xa1\xb6i\xdaG\xc6\x88@\xf6\xc3\x81\xc0u|)\x119x0\t\xfc\x81\x1f\xa1\xcb\xf9\xceC\x83\x820')
            bytes
        """
        if type(key) == bytes and len(key) == 32: return SXTKeyEncodings.BYTES
        try:
            bytes.fromhex(key)
            return SXTKeyEncodings.HEX
        except:
            if type(key) == str and len(key) == 44: return SXTKeyEncodings.BASE64
        raise SxTKeyEncodingError(f'Unknown Encoding: {key}', logger=self.logger)


    def new_keypair(self) -> dict:
        """--------------------
        Generate a new ED25519 keypair, set class variables and return dictionary of values.

        Returns: 
            dict: New keypair values

        Examples: 
            >>> km = SXTKeyManager(SXTKeyEncodings.BASE64)
            >>> km.new_keypair
            ['private_key', 'public_key']
            >>> len( km.private_key )
            64
            >>> km.encoding = SXTKeyEncodings.BASE64
            >>> len( km.private_key )
            44
         """
        keypair = KeyPair()
        self.private_key = bytes(keypair.private_key.to_bytes())
        return { 'private_key': self.private_key
                ,'public_key':  self.public_key }


    def convert_key(self, key, encoding_in:SXTKeyEncodings = SXTKeyEncodings.BYTES
                             , encoding_out:SXTKeyEncodings = SXTKeyEncodings.HEX):
        """--------------------
        Converts a key value from one stated format into requested encoding format.

        Args: 
            key (any): Key value, typically either str [base64, hex] or bytes.
            encoding_in (str):  Encoding of supplied key, as SXTKeyEncodings
            encoding_out (str): Encoding of returned key, as SXTKeyEncodings
        
        Return: 
            dict: Converted key the encoding_out encoding.

        Examples:
            >>> SXTKeyManager().convert_key('0123456789abcdef', SXTKeyEncodings.HEX, SXTKeyEncodings.BASE64)
            ASNFZ4mrze8=
            >>> SXTKeyManager().convert_key('ASNFZ4mrze8=', SXTKeyEncodings.BASE64, SXTKeyEncodings.HEX)
            0123456789abcdef
        """
        try:
            # always take to bytes first
            if not key:
                key_bytes = bytes(b'')
            elif encoding_in == SXTKeyEncodings.BYTES:
                key_bytes = bytes(key)
            elif encoding_in == SXTKeyEncodings.BASE64:
                key_bytes = base64.b64decode(key)
            elif encoding_in == SXTKeyEncodings.HEX:
                key_bytes = bytes.fromhex(key)

            # format as requested encoding
            if encoding_out == SXTKeyEncodings.BYTES:
                key_out = key_bytes
            elif encoding_out == SXTKeyEncodings.BASE64:
                key_out = base64.b64encode(key_bytes).decode('utf-8')
            elif encoding_out == SXTKeyEncodings.HEX:
                key_out = key_bytes.hex()

            # self.logger.debug(f'Key verified and converted from {encoding_in.name} to {encoding_out.name}.')
            return key_out
        except Exception as ex:
            error = ex
        raise SxTKeyEncodingError(f'Error: {error}, going from {encoding_in.name} to {encoding_out.name}', logger=self.logger)


    def get_KeyPair(self) ->KeyPair:
        """Builds and returns a KeyPair object from current private / public key."""
        if not self.__pv: 
            raise ValueError('Requires valid private_key to be set')
        kp = KeyPair.from_private_key( PrivateKey.from_bytes(self.__pv) )
        return kp


    def sign_message(self, message:str, encoding_out:SXTKeyEncodings = SXTKeyEncodings.HEX):
        """--------------------
        Use private key to cryptographically sign and return message.

        Args: 
            message (str): String message to sign with the class private key and return.
            encoding_out (SXTKeyEncodings): Encoding of returned signed message, as SXTKeyEncodings
            
        Returns:
            str | bytes: Signed message, encoded per encoded_out (or class.encoding as default)

        """
        try:
            if not encoding_out: encoding_out = self.encoding
            signing_object = nacl.signing.SigningKey(bytes(self.__pv))
            signed_message = signing_object.sign(message.encode('utf-8'))
            return self.convert_key(signed_message.signature, SXTKeyEncodings.BYTES, encoding_out)
        except Exception as ex:
            error = ex
        raise SxTKeyEncodingError(error, logger=self.logger)
        

    def add_keychange_callback(self, func) -> None:
        """Adds a function to a list of functions to call whenever a key (public or private) changes."""
        if type(self.keychange_callback_func_list) != list: self.keychange_callback_func_list = []
        self.keychange_callback_func_list.append(func)


    def clear_keychange_callback(self) -> None:
        """Clears all functions from the keychange callback list."""
        self.keychange_callback_func_list = []



if __name__ == '__main__':

    print('\n', '-=-='*10, '\n' )

    # BASIC USAGE
    key1 = SXTKeyManager(new_keypair=True)
    key1.new_keypair()  # or, explicitly

    # objects come with default root logger with debug msgs to stdout
    key1.logger.debug( key1 )
    print( 'signed message:', key1.sign_message('my signed message') )



    # Supply your own setup to the constructor
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    if len(logger.handlers) == 0: logger.addHandler( logging.StreamHandler() )
    
    key2 = SXTKeyManager(private_key = '4G7l7Zu4zTTMsV/p3i7qjNEqf2LV92LSXfntQXWkH+c=', 
                         encoding = SXTKeyEncodings.HEX, 
                         keychange_callback_func = print, # function called on key-change
                         logger=logger
                         )
    # during instantiation, private key is set, and that change triggers the callback 'print'
    # then the public key is regenerated, again triggering the callback 'print'.
    # The two outputs have different 'key_changed' values: one private_key, one public_key.

    # casting or printing as a string (__str__) provides a human-readable string output:
    print( key2 , '\n' + '-'*10 )

    # to print the object without private key truncation, try the repr() function:
    print( repr(key2) )

     

    # you can have many callback functions, which fire on any key value change
    import pprint
    key2.clear_keychange_callback()
    key2.encoding = SXTKeyEncodings.BASE64

    print( '-'*10, 'adding callbacks...')
    key2.add_keychange_callback( print ) 
    key2.add_keychange_callback( pprint.pprint )
    key2.add_keychange_callback( lambda x: print(f"\tKey that Changed: {x['key_changed']}") )

    # triggers 6 callbacks: 3 for the private key change, which triggers 3 more with a public key rebuild
    key2.private_key = 'mOXd6UzMNiR1qfQYW/MRcVANdxP+k62JGYXo2t5Ukv0='
    
    # this only happens on change, not every time the item is inspected.
    print( key2.public_key )
    print( key2.private_key )
    

    # the encoding property only controls the encoding OUTPUT.  
    # All encoding INPUT is automatically detected and stored as bytes (note debug message)
    key2.clear_keychange_callback()
    key2.add_keychange_callback( lambda x: print('\t', x['private_key'] ) )
    key2.logger.setLevel( logging.INFO )

    for encoding in [ SXTKeyEncodings.HEX, SXTKeyEncodings.BASE64, SXTKeyEncodings.BYTES]:
        key2.encoding = encoding
        print( encoding.name )
        key2.private_key = '4G7l7Zu4zTTMsV/p3i7qjNEqf2LV92LSXfntQXWkH+c='
        key2.private_key = 'e06ee5ed9bb8cd34ccb15fe9de2eea8cd12a7f62d5f762d25df9ed4175a41fe7'
        key2.private_key = b'\xe0n\xe5\xed\x9b\xb8\xcd4\xcc\xb1_\xe9\xde.\xea\x8c\xd1*\x7fb\xd5\xf7b\xd2]\xf9\xedAu\xa4\x1f\xe7'


    # Access the native KeyPair object, if needed:
    key2.encoding = SXTKeyEncodings.BYTES
    privatekey_obj = key2.get_KeyPair().private_key.from_bytes( key2.private_key )
    print( privatekey_obj.to_hex() )
    

    # note: key properties will convert keys from BYTES to requested encoding 
    # upon inspection - even by the IDE.   Try hover-over inspecting in an IDE
    # and notice the debug log entries.
    key2.logger.setLevel( logging.DEBUG )
    key2.encoding = SXTKeyEncodings.BASE64
    key2.private_key
    key2.public_key

    pass