from enum import Enum

class SXTPermission(Enum):
    SELECT = 'dql_select'
    INSERT = 'dml_insert'
    UPDATE = 'dml_update'
    DELETE = 'dml_delete'
    MERGE  = 'dml_merge'
    CREATE = 'ddl_create'
    ALTER  = 'ddl_alter'
    DROP   = 'ddl_drop'
    ALL    = '*'
    def __str__(self) -> str:
        return super().__str__()
    

class SXTKeyEncodings(Enum):
    HEX = 'hex'
    BASE64 = 'base64'
    BYTES = 'bytes'
    def __str__(self) -> str:
        return super().__str__()
    
    
class SXTApiCallTypes(Enum):
    POST = 'post'
    GET = 'get'
    PUT = 'put'
    DELETE = 'delete'
    def __str__(self) -> str:
        return super().__str__()
    

class SXTSqlType(Enum):
    DDL = 'ddl'
    DML = 'dml'
    DQL = 'dql'
    def __str__(self) -> str:
        return super().__str__()
    

class SXTOutputFormat(Enum):
    JSON = 'json'
    CSV = 'csv'
    DATAFRAME = 'dataframe'
    PARQUET = 'parquet'
    def __str__(self) -> str:
        return super().__str__()
    
    
class SXTTableAccessType(Enum):
    PERMISSIONED = 'permissioned'
    PUBLIC_READ = 'public_read'
    PUBLIC_APPEND = 'public_append'
    PUBLIC_WRITE = 'public_write'
    def __str__(self) -> str:
        return super().__str__()
    

class SXTResourceType(Enum):
    UNDEFINED = 'undefined'
    TABLE = 'table_name'
    VIEW = 'view_name'
    MATERIALIZED_VIEW = 'matview_name'
    PARAMETERIZED_VIEW = 'parmview_name'
    KAFKA_STREAM = 'kafka_name'
    def __str__(self) -> str:
        return super().__str__()
    

class SXTDiscoveryScope(Enum):
    SUBSCRIPTION = 'subscription'
    PUBLIC = 'public'
    ALL = 'all'
    def __str__(self) -> str:
        return super().__str__()
    
