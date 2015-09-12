module Qualys.Types.Was where

import           Data.Text (Text)
import qualified Data.ByteString as B
import           Data.Time (UTCTime)

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
    } deriving Show

data WsScanProfile = WsScanProfile
    { wspId   :: Maybe Int  -- ^ ID of the option profile
    , wspName :: Maybe Text -- ^ Option profile name
    } deriving Show

data WsTarget = WsTarget
    { wstWebApps   :: Maybe [WsWebApp]
    , wstTags      :: Maybe [WsTag]
    , wstWebApp    :: WsWebApp
    , wstAuthRec   :: Maybe WsAuthRec
    , wstScanAppl  :: Maybe ScanAppl -- ^ Scanner Appliance
    , wstCancelOpt :: Maybe Text    -- ^ Cancel option
    , wstProxy     :: Maybe WsProxy -- ^ Proxy settings
    } deriving Show

data WsWebApp = WsWebApp
    { wsWebAppId   :: Maybe Int
    , wsWebAppName :: Maybe Text
    , wsWebAppUrl  :: Maybe Text
    } deriving Show

data WsTag = WsTag
    { wstId   :: Int
    , wstName :: Maybe Text
    } deriving Show
data WsAuthRec = WsAuthRec
    { wsaId   :: Maybe Int
    , wsaName :: Maybe Text
    } deriving Show

data WsProxy = WsProxy
    { wsprId   :: Maybe Int  -- ^ Proxy ID for scanning the app
    , wsprName :: Maybe Text -- ^ Proxy name
    , wsprUrl  :: Maybe Text -- ^ Proxy URL
    } deriving Show

data WsUser = WsUser
    { wsuId        :: Maybe Int
    , wsuUsername  :: Maybe Text
    , wsuFirstName :: Maybe Text
    , wsuLastName  :: Maybe Text
    } deriving Show

data WsSummary = WsSummary
    { wssCrawlDur :: Maybe Int
    , wssTestDur  :: Maybe Int
    , wssLnkCrawl :: Maybe Int
    , wssRequests :: Maybe Int
    , wssResStat  :: Text
    , wssAuthStat :: Text
    , wssOs       :: Maybe Text
    } deriving Show

data WsStat = WsStat
    { wssGlobal :: Maybe WsGlobalStat
    , wssGroup  :: Maybe [WsNameStat]
    , wssOwasp  :: Maybe [WsNameStat]
    , wssWasc   :: Maybe [WsNameStat]
    } deriving Show

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

data WsNameStat = WsNameStat
    { wsnName  :: Text
    , wsnTotal :: Int
    , wsnLev5  :: Int
    , wsnLev4  :: Int
    , wsnLev3  :: Int
    , wsnLev2  :: Int
    , wsnLev1  :: Int
    } deriving Show

data WsScanResult = WsScanResult
    { wsrQid     :: Int
    , wsrTitle   :: Text
    , wsrUri     :: Text
    , wsrParam   :: Maybe Text
    , wsrContent :: Maybe Text
    , wsrInsts   :: Maybe [WsInstance]
    } deriving Show

data WsInstance = WsInstance
    { wiAuth     :: Bool
    , wiForm     :: Maybe Text
    , wiPayloads :: Maybe [WsPayload]
    } deriving Show

data WsPayload = WsPayload
    { wpPayload :: Text
    , wpResult  :: B.ByteString
    } deriving Show

data WsIg = WsIg
    { wigQid   :: Int
    , wigTitle :: Text
    , wigData  :: B.ByteString
    } deriving Show

data ScanAppl = ScanAppl
    { saType         :: Text
    , saFriendlyName :: Maybe Text
    } deriving Show

data WebApp = WebApp
    { waId :: Int
    , waName :: Maybe Text
    , waUrl  :: Maybe Text
    , waOs   :: Maybe Text
    , waOwner :: Maybe WsUser
    , waScope :: Maybe Text
    , waSubDomain :: Maybe Text
    , waDomains :: Maybe [Text]
    , waUris :: Maybe [Text]
    , waAttrs :: Maybe [(Text,Text)]
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
    , waLastScan   :: Maybe WasScan
    , waCreatedBy  :: Maybe WsUser
    , waCreateDate :: Maybe UTCTime
    , waUpdateBy   :: Maybe WsUser
    , waUpdateDate :: Maybe UTCTime
    , waScreenshot :: Maybe B.ByteString
    , waProxy      :: Maybe WsProxy
    , waConfig     :: Maybe WaConfig
    } deriving Show

data UrlEntry = UrlText  Text
              | UrlRegex Text
              deriving Show

data Comment = Comment
    { cmContent :: Text
    , cmAuthor  :: Maybe WsUser
    , cmDate    :: Maybe UTCTime
    } deriving Show

data WaConfig = CancelAfterN Int
              | CancelScanAt Text
              deriving Show
