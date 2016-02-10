-- | Types for Web Application Scanning
module Qualys.Types.Was where

import           Data.Text (Text)
import qualified Data.ByteString as B
import           Data.Time (UTCTime)

import           Qualys.Internal

-- | Was scan
data WasScan = WasScan
    { wsId          :: Int          -- ^ Scan ID
    , wsName        :: Maybe Text   -- ^ Scan name
    , wsRef         :: Maybe Text
    , wsType        :: Maybe Text
    , wsMode        :: Maybe Text   -- ^ ONDEMAND, SCHEDULED or API
    , wsMulti       :: Maybe Bool
    , wsProgScan    :: Maybe Bool
    , wsTarget      :: Maybe WsTarget -- ^ Target of the web scan
    , wsProfile     :: Maybe WsScanProfile -- ^ Option profile
    , wsCancAftNHrs :: Maybe Int
    , wsCancTime    :: Maybe Text
    , wsOptions     :: Maybe [(Text,Text)]
    , wsLaunch      :: Maybe UTCTime -- ^ Date and time the scan was launched
    , wsLaunchBy    :: Maybe WsUser  -- ^ User who launched the scan
    , wsStatus      :: Maybe Text    -- ^ Scan status (SUBMITTED, RUNNING, FINISHED, ERROR or CANCELED).
    , wsEndDt       :: Maybe UTCTime -- ^ Date and time the scan ended
    , wsScanDur     :: Maybe Int     -- ^ Duration of the scan in ???
    , wsSummary     :: Maybe WsSummary
    , wsStats       :: Maybe WsStat
    , wsVulns       :: Maybe [WsScanResult]
    , wsSensCont    :: Maybe [WsScanResult]
    , wsIgs         :: Maybe [WsIg]
    , wsSendMail    :: Maybe Bool
    } deriving Show

-- | Was scan profile
data WsScanProfile = WsScanProfile
    { wspId   :: Maybe Int  -- ^ ID of the option profile
    , wspName :: Maybe Text -- ^ Option profile name
    } deriving Show

-- | Was scan target
data WsTarget = WsTarget
    { wstWebApps   :: Maybe [WsWebApp]
    , wstTags      :: Maybe [WsTag]
    , wstWebApp    :: WsWebApp
    , wstAuthRec   :: Maybe WsAuthRec
    , wstScanAppl  :: Maybe ScanAppl -- ^ Scanner Appliance
    , wstCancelOpt :: Maybe Text    -- ^ Cancel option
    , wstProxy     :: Maybe WsProxy -- ^ Proxy settings
    } deriving Show

-- | Web application
data WsWebApp = WsWebApp
    { wsWebAppId   :: Maybe Int
    , wsWebAppName :: Maybe Text
    , wsWebAppUrl  :: Maybe Text
    } deriving Show

-- | Tag data
data WsTag = WsTag
    { wstId   :: Int
    , wstName :: Maybe Text
    } deriving Show

-- | Authentication record
data WsAuthRec = WsAuthRec
    { wsaId         :: Int
    , wsaName       :: Maybe Text
    , wsaOwner      :: Maybe WsUser
    , wsaFormRec    :: Maybe WaFormRecord
    , wsaServRec    :: Maybe ServRecord
    , wsaTags       :: Maybe [WsTag]
    , wsaComments   :: Maybe [Comment]
    , wsaCreateDate :: Maybe UTCTime
    , wsaCreatedBy  :: Maybe WsUser
    , wsaUpdateDate :: Maybe UTCTime
    , wsaUpdateBy   :: Maybe WsUser
    } deriving Show

-- | Proxy information
data WsProxy = WsProxy
    { wsprId   :: Maybe Int  -- ^ Proxy ID for scanning the app
    , wsprName :: Maybe Text -- ^ Proxy name
    , wsprUrl  :: Maybe Text -- ^ Proxy URL
    } deriving Show

-- | User data
data WsUser = WsUser
    { wsuId        :: Maybe Int
    , wsuUsername  :: Maybe Text
    , wsuFirstName :: Maybe Text
    , wsuLastName  :: Maybe Text
    } deriving Show

-- | Web scan summary
data WsSummary = WsSummary
    { wssCrawlDur :: Maybe Int
    , wssTestDur  :: Maybe Int
    , wssLnkCrawl :: Maybe Int
    , wssRequests :: Maybe Int
    , wssResStat  :: Text
    , wssAuthStat :: Text
    , wssOs       :: Maybe Text
    } deriving Show

-- | Web scan stats
data WsStat = WsStat
    { wssGlobal :: Maybe WsGlobalStat -- ^ Global stats
    , wssGroup  :: Maybe [WsNameStat] -- ^ Group stats
    , wssOwasp  :: Maybe [WsNameStat] -- ^ OWASP stats ()
    , wssWasc   :: Maybe [WsNameStat] -- ^ WASC stats
    } deriving Show

-- | Web scan global stats
data WsGlobalStat = WsGlobalStat
    { wsgVulnTotal :: Int
    , wsgVulnLev5  :: Int
    , wsgVulnLev4  :: Int
    , wsgVulnLev3  :: Int
    , wsgVulnLev2  :: Int
    , wsgVulnLev1  :: Int
    , wsgScsTotal  :: Int
    , wsgScsLev5   :: Int
    , wsgScsLev4   :: Int
    , wsgScsLev3   :: Int
    , wsgScsLev2   :: Int
    , wsgScsLev1   :: Int
    , wsgIgsTotal  :: Int
    , wsgIgsLev5   :: Int
    , wsgIgsLev4   :: Int
    , wsgIgsLev3   :: Int
    , wsgIgsLev2   :: Int
    , wsgIgsLev1   :: Int
    } deriving Show

-- | Named stat
data WsNameStat = WsNameStat
    { wsnName  :: Text
    , wsnTotal :: Int
    , wsnLev5  :: Int
    , wsnLev4  :: Int
    , wsnLev3  :: Int
    , wsnLev2  :: Int
    , wsnLev1  :: Int
    } deriving Show

-- | Scan Result
data WsScanResult = WsScanResult
    { wsrQid     :: QID
    , wsrTitle   :: Text
    , wsrUri     :: Text
    , wsrParam   :: Maybe Text
    , wsrContent :: Maybe Text
    , wsrInsts   :: Maybe [WsInstance]
    } deriving Show

-- | Instance
data WsInstance = WsInstance
    { wiAuth     :: Bool
    , wiForm     :: Maybe Text
    , wiPayloads :: Maybe [WsPayload]
    } deriving Show

-- | Payload
data WsPayload = WsPayload
    { wpPayload :: Text
    , wpResult  :: B.ByteString
    } deriving Show

-- | Information gathered
data WsIg = WsIg
    { wigQid   :: QID
    , wigTitle :: Text
    , wigData  :: B.ByteString
    } deriving Show

-- | Scanner appliance
data ScanAppl = ScanAppl
    { saType         :: Text
    , saFriendlyName :: Maybe Text
    } deriving Show

-- | Web application
data WebApp = WebApp
    { waId         :: Int
    , waName       :: Maybe Text
    , waUrl        :: Maybe Text
    , waOs         :: Maybe Text
    , waOwner      :: Maybe WsUser
    , waScope      :: Maybe Text
    , waSubDomain  :: Maybe Text
    , waDomains    :: Maybe [Text]
    , waUris       :: Maybe [Text]
    , waAttrs      :: Maybe [(Text,Text)]
    , waDefProfile :: Maybe WsScanProfile
    , waDefScanner :: Maybe ScanAppl
    , waScanLocked :: Maybe Bool
    , waProgScan   :: Maybe Bool
    , waUrlBlList  :: Maybe [UrlEntry]
    , waUrlWhList  :: Maybe [UrlEntry]
    , waPostBlList :: Maybe [UrlEntry]
    , waAuthRec    :: Maybe [WsAuthRec]
    , waUseRobots  :: Maybe Text
    , waUseSitemap :: Maybe Bool
    , waHeaders    :: Maybe [Text]
    , waMalwareMon :: Maybe Bool
    , waMalwareNot :: Maybe Bool
    , waMwSchTime  :: Maybe UTCTime
    , waMwSchTz    :: Maybe Text -- XXX:
    , waTags       :: Maybe [WsTag]
    , waComments   :: Maybe [Comment]
    , waIsSched    :: Maybe Bool
    , waLastScan   :: Maybe WasScanInfo
    , waCreatedBy  :: Maybe WsUser
    , waCreateDate :: Maybe UTCTime
    , waUpdateBy   :: Maybe WsUser
    , waUpdateDate :: Maybe UTCTime
    , waScreenshot :: Maybe B.ByteString
    , waProxy      :: Maybe WsProxy
    , waConfig     :: Maybe WaConfig
    } deriving Show

-- | Url entry
data UrlEntry = UrlText  Text
              | UrlRegex Text
              deriving Show

-- | Comment
data Comment = Comment
    { cmContent :: Text
    , cmAuthor  :: Maybe WsUser
    , cmDate    :: Maybe UTCTime
    } deriving Show

-- | Scan Info
data WasScanInfo = WasScanInfo
    { wsiId   :: Int
    , wsiName :: Maybe Text
    } deriving Show

-- | Web app config
data WaConfig = CancelAfterN Int
              | CancelScanAt Text
              deriving Show

data WaFormRecord = WaFormRecord
    { wafrType      :: Maybe Text
    , wafrSslOnly   :: Maybe Bool
    , wafrSelScript :: Maybe SelScript
    , wafrFields    :: Maybe [WfrField]
    } deriving Show

data WfrField = WfrField
    { frId      :: Int
    , frName    :: Maybe Text
    , frSecured :: Maybe Bool
    , frValue   :: Maybe Text
    } deriving Show

data SelScript = SelScript
    { ssName  :: Maybe Text
    , ssData  :: Maybe Text
    , ssRegex :: Maybe Text
    } deriving Show

data ServRecord = ServRecord
    { srSslOnly :: Maybe Bool
    , srCert    :: Maybe Certificate
    , srFields  :: Maybe [SrField]
    } deriving Show

data SrField = SrField
    { srfId     :: Int
    , srfType   :: Maybe Text
    , srfDomain :: Maybe Text
    , srfUser   :: Maybe Text
    , srfPass   :: Maybe Text
    } deriving Show

data Certificate = Certificate
    { ctName       :: Maybe Text
    , ctContents   :: Maybe Text
    , ctPassphrase :: Maybe Text
    } deriving Show
