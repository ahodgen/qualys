{-# LANGUAGE OverloadedStrings, FlexibleInstances #-}
-- | For practical examples see "Qualys.Cookbook.HostListDetection".
module Qualys.HostListDetection
    (
    -- * Actions
      runHostListDetection
    , getHostListDetection
    -- * Options
    , hldoActKernelOnly
    , hldoIds
    , hldoIdMin
    , hldoIdMax
    , hldoIps
    , hldoAgIds
    , hldoAgTitles
    , hldoNetworkIds
    , hldoVmScanSince
    , hldoNoVmScanSince
    , hldoDaysSinceVmScan
    , hldoStatus
    , hldoComplEnabled
    , hldoOsPattern
    , hldoQids
    , hldoSeverities
    , hldoShowIgs
    , hldoInclSearchListTitles
    , hldoExclSearchListTitles
    , hldoInclSearchListIds
    , hldoExclSearchListIds
    , hldoTruncLimit
    -- * Types
    , Host (..)
    , Detection (..)
    , Tag (..)
    ) where

import           Prelude hiding (mapM)
import           Control.Applicative hiding (many)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Control.Monad.Trans.Class (lift)
import           Control.Monad.Trans.Resource (MonadThrow)
import qualified Data.ByteString.Char8 as B8
import           Data.Conduit (($$), ConduitM)
import           Data.Maybe (fromMaybe)
import           Data.Monoid ((<>), Monoid (..))
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Traversable (mapM)
import           Data.Time (UTCTime, getCurrentTime)
import           Data.XML.Types
import           Network.HTTP.Client
import           Network.HTTP.Types (renderQuery)
import           Text.XML.Stream.Parse

import           Qualys.Internal
import           Qualys.V2api

-- * Options for the Qualys Host List Detection API

-- | Include (False) or exclude (True) vulnerabilities found on
--   non-running Linux kernels.
hldoActKernelOnly :: Bool -> Param
hldoActKernelOnly x = ("active_kernels_only", toOptBool x)

-- | List of host IDs to retrieve.
hldoIds :: (Integral a, Show a) => [a] -> Param
hldoIds xs = ("ids", toOptList toOptInt xs)

-- | Get QIDs greater to or equal this value.
hldoIdMin :: (Integral a, Show a) => a -> Param
hldoIdMin x = ("id_min", toOptInt x)

-- | Get QIDs less than or equal this value.
hldoIdMax :: (Integral a, Show a) => a -> Param
hldoIdMax x = ("id_max", toOptInt x)

-- | Retrieve entries for certain IPs.
hldoIps :: OptValText a => [a] -> Param
hldoIps xs = ("ips", toOptList toOptTxt xs)

-- | Retrieve hosts belonging to certain asset group IDs.
hldoAgIds :: (Integral a, Show a) => [a] -> Param
hldoAgIds xs = ("ag_ids", toOptList toOptInt xs)

-- | Retrieve hosts belonging to certain asset groups.
hldoAgTitles :: OptValText a => [a] -> Param
hldoAgTitles xs = ("ag_titles", toOptList toOptTxt xs)

-- | Get certain network IDs.
hldoNetworkIds :: (Integral a, Show a) => [a] -> Param
hldoNetworkIds xs = ("network_ids", toOptList toOptInt xs)

-- | Get entries that have been scanned since the given time.
hldoVmScanSince :: OptValTime a => a -> Param
hldoVmScanSince x = ("vm_scan_since", toOptTm x)

-- | Get entries that have not been scanned since the given time.
hldoNoVmScanSince :: OptValTime a => a -> Param
hldoNoVmScanSince x = ("no_vm_scan_since", toOptTm x)

-- | Retrieve hosts processed in the last number of days.
hldoDaysSinceVmScan :: (Integral a, Show a) => a -> Param
hldoDaysSinceVmScan x = ("max_days_since_last_vm_scan", toOptInt x)

-- | Get entries with certain status.
hldoStatus :: OptValText a => [a] -> Param
hldoStatus xs = ("status", toOptList toOptTxt xs)

-- | Fetch processed hosts assigned (True) or not assigned (False) to the
--   policy compliance module
hldoComplEnabled :: Bool -> Param
hldoComplEnabled x = ("compliance_enabled", toOptBool x)

-- | Retrieve hosts where the operating system detected matches a PCRE
--   regex.
hldoOsPattern :: OptValText a => a -> Param
hldoOsPattern x = ("os_pattern", toOptTxt x)

-- | Grab detection records with these QIDs.
hldoQids :: (Integral a, Show a) => [a] -> Param
hldoQids xs = ("qids", toOptList toOptInt xs)

-- | Fetch detection records with certain severities.
hldoSeverities :: (Integral a, Show a) => [a] -> Param
hldoSeverities xs = ("severities", toOptList toOptInt xs)

-- | Show (True) or hide (False) detection records
--   with \"Information Gathered.\"
hldoShowIgs :: Bool -> Param
hldoShowIgs x = ("show_igs", toOptBool x)

-- | Show detection records when its QID is in the one or more of these
--   search list titles.
hldoInclSearchListTitles :: OptValText a => [a] -> Param
hldoInclSearchListTitles xs = ("include_search_list_titles"
                              , toOptList toOptTxt xs)

-- | Show detection records when its QID is not in the one or more of these
--   search list titles.
hldoExclSearchListTitles :: OptValText a => [a] -> Param
hldoExclSearchListTitles xs = ("exclude_search_list_titles"
                              , toOptList toOptTxt xs)

-- | Show detection records when its QID is in the one or more of these
--   search lists.
hldoInclSearchListIds :: (Integral a, Show a) => [a] -> Param
hldoInclSearchListIds xs = ("include_search_list_ids"
                           , toOptList toOptInt xs)

-- | Show detection records when its QID is not in the one or more of these
--   search lists.
hldoExclSearchListIds :: (Integral a, Show a) => [a] -> Param
hldoExclSearchListIds xs = ("exclude_search_list_ids"
                           , toOptList toOptInt xs)

-- | How many result to return per request (default is 1000)
hldoTruncLimit :: (Integral a, Show a) => a -> Param
hldoTruncLimit x = ("truncation_limit", toOptInt x)

data Host = Host
    { hldId        :: Text          -- ^ Host ID assigned by Qualys
    , hldIP        :: Maybe Text    -- ^ IPv4 address
    , hldIPv6      :: Maybe Text    -- ^ IPv6 address
    , hldTrackMeth :: Maybe Text    -- ^ Tracking Method (IP,DNS, or NETBIOS)
    , hldOs        :: Maybe Text    -- ^ Operating system detected
    , hldOsCpe     :: Maybe Text
    , hldDns       :: Maybe Text    -- ^ DNS name
    , hldNetBIOS   :: Maybe Text    -- ^ NetBIOS name
    , hldQgHostId  :: Maybe Text    -- ^ Host ID when agentless tracking used
    , hldLastScan  :: Maybe UTCTime -- ^ Date/time of last scan of host
    , hldTags      :: Maybe [Tag]   -- ^ Tags associated with host
    , hldDetect    :: Maybe [Detection] -- ^ Detections
    } deriving (Show, Eq)

data Detection = Detection
    { dQid      :: Text          -- ^ QID (Qualys ID) for this vuln
    , dType     :: Text          -- ^ Type of vuln (Confirmed, Potential, Info)
    , dSev      :: Maybe Int     -- ^ Severity
    , dPort     :: Maybe Int     -- ^ Port this vuln was detected on
    , dProtocol :: Maybe Text    -- ^ Protocol
    , dFqdn     :: Maybe Text    -- ^ Fully qualified domain name
    , dSsl      :: Maybe Bool    -- ^ Was this detected over SSL?
    , dInst     :: Maybe Text -- ^ Oracle DB inst. where this vuln was detected
    , dResult   :: Maybe Text    -- ^ Scan test results
    , dStatus   :: Maybe Text    -- ^ Status of this vulnerability
    , dFstFound :: Maybe UTCTime -- ^ Date/time this vuln was first found
    , dLstFound :: Maybe UTCTime -- ^ Date/time this vuln was last found
    , dLstTest  :: Maybe UTCTime -- ^ Date/time this vuln was tested
    , dLstUpdte :: Maybe UTCTime -- ^ Date/time this record was updated
    , dLstFixed :: Maybe UTCTime -- ^ Date/time this vuln was verified fixed
    } deriving (Show, Eq)

data Tag = Tag
    { tId      :: Maybe Text -- ^ Tag ID
    , tName    :: Text       -- ^ Tag Name
    , tColor   :: Maybe Text -- ^ Color
    , tBgColor :: Maybe Text -- ^ Background color
    } deriving (Show, Eq)

parseDoc :: (MonadThrow  m, Monoid a) => (Host -> m a) ->
            ConduitM Event o m (Maybe V2Resp, a)
parseDoc tm =
    requireTagNoAttr "HOST_LIST_VM_DETECTION_OUTPUT" $ parseResp tm

parseResp :: (MonadThrow m, Monoid a) => (Host -> m a) ->
             ConduitM Event o m (Maybe V2Resp, a)
parseResp tm = requireTagNoAttr "RESPONSE" $ do
    parseDiscard "DATETIME"
    hs <- parseHosts tm
    w  <- parseWarning
    return (w, hs)

parseHosts :: (MonadThrow m, Monoid a) => (Host -> m a) -> ConduitM Event o m a
parseHosts tm = do
    x <- tagNoAttr "HOST_LIST" $ many (parseHost tm)
    return . mconcat . fromMaybe [] $ x

-- | Parse host record and apply it to f
parseHost :: MonadThrow  m => (Host -> m a) -> ConduitM Event o m (Maybe a)
parseHost f = mapM (lift . f) =<<
    tagNoAttr "HOST" (Host
        <$> requireTagNoAttr "ID" content
        <*> tagNoAttr "IP" content
        <*> tagNoAttr "IPV6" content
        <*> tagNoAttr "TRACKING_METHOD" content
        <*> tagNoAttr "OS" content
        <*> tagNoAttr "OS_CPE" content
        <*> tagNoAttr "DNS" content
        <*> tagNoAttr "NETBIOS" content
        <*> tagNoAttr "QG_HOSTID" content
        <*> optionalWith parseDate (tagNoAttr "LAST_SCAN_DATETIME" content)
        <*> parseTags
        <*> parseDetections)

parseTags :: MonadThrow m => ConduitM Event o m (Maybe [Tag])
parseTags = tagNoAttr "TAGS" $ many parseTag

-- | Parse asset tag
parseTag :: MonadThrow m => ConduitM Event o m (Maybe Tag)
parseTag = tagNoAttr "TAG" $ Tag
    <$> tagNoAttr "TAG_ID" content
    <*> requireTagNoAttr "NAME" content
    <*> tagNoAttr "COLOR" content
    <*> tagNoAttr "BACKGROUND_COLOR" content

parseDetections :: MonadThrow m => ConduitM Event o m (Maybe [Detection])
parseDetections = tagNoAttr "DETECTION_LIST" $ many parseDetection

-- | Parse detections (i.e. vulnerabilities found)
parseDetection :: MonadThrow m => ConduitM Event o m (Maybe Detection)
parseDetection = tagNoAttr "DETECTION" $ Detection
    <$> requireTagNoAttr "QID" content
    <*> requireTagNoAttr "TYPE" content
    <*> optionalWith parseUInt (tagNoAttr "SEVERITY" content)
    <*> optionalWith parseUInt (tagNoAttr "PORT" content)
    <*> tagNoAttr "PROTOCOL" content
    <*> tagNoAttr "FQDN" content
    <*> optionalWith parseBool (tagNoAttr "SSL" content)
    <*> tagNoAttr "INSTANCE" content
    <*> tagNoAttr "RESULTS" content
    <*> tagNoAttr "STATUS" content
    <*> optionalWith parseDate (tagNoAttr "FIRST_FOUND_DATETIME" content)
    <*> optionalWith parseDate (tagNoAttr "LAST_FOUND_DATETIME"  content)
    <*> optionalWith parseDate (tagNoAttr "LAST_TEST_DATETIME"   content)
    <*> optionalWith parseDate (tagNoAttr "LAST_UPDATE_DATETIME" content)
    <*> optionalWith parseDate (tagNoAttr "LAST_FIXED_DATETIME"  content)

getPage :: (Monoid a, MonadIO m, MonadThrow m) =>
           (Host -> QualysT m a) -> Maybe String ->
           QualysT m (Maybe V2Resp, a)
getPage _ Nothing = return (Nothing, mempty)
getPage f (Just uri) = do
    now <- liftIO getCurrentTime
    liftIO . putStrLn $ show now <> " " <> uri
    res <- fetchV2Get uri
    now' <- liftIO getCurrentTime
    liftIO . putStrLn $ show now' <> " DONE FETCH"
    parseLBS def (responseBody res) $$ parseDoc f

-- | Keep requesting records until we've processed everything, or failed.
runHld :: (MonadIO m, MonadThrow m, Monoid a) =>
          (Host -> QualysT m a) -> Maybe String -> QualysT m a
runHld f uri = do
    (ret,xs) <- getPage f uri
    case ret of
        Nothing -> return xs
        Just r  -> case v2rCode r of
                    Just "1980" -> do
                        ys <- runHld f (T.unpack <$> v2rUrl r)
                        return (ys <> xs)
                    _           -> do
                        liftIO . print . v2rMsg $ r
                        return xs

paramsToQuery :: [Param] -> String
paramsToQuery xs = B8.unpack . renderQuery True . fmap p2q . uniqueParams $ xs
  where
    p2q (a,b) = (a,Just b)

-- | Run a function for every entry returned from Host List Detection and
--   collect the results.
runHostListDetection :: (Monoid a, MonadIO m, MonadThrow m) =>
                        [Param] -> (Host -> QualysT m a) -> QualysT m a
runHostListDetection ps f = do
    let query = paramsToQuery $ [("action", "list")] <> ps
    base <- buildV2ApiUrl "asset/host/vm/detection/"
    runHld f (Just $ base <> query)

-- | Get entries from Host List Detection.
getHostListDetection :: (MonadIO m, MonadThrow m) => [Param] -> QualysT m [Host]
getHostListDetection ps = runHostListDetection ps (\x -> return [x])
