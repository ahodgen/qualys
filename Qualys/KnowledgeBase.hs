{-# LANGUAGE OverloadedStrings, DeriveDataTypeable #-}
-- | For practical examples see "Qualys.Cookbook.KnowledgeBase".
module Qualys.KnowledgeBase
    (
    -- * Actions
      runKnowledgeBase
    , getKnowledgeBase
    -- * Options
    , kboModAfter
    , kboModBefore
    , kboPubAfter
    , kboPubBefore
    , kboUserModAfter
    , kboUserModBefore
    , kboServiceModAfter
    , kboServiceModBefore
    , kboIdMin
    , kboIdMax
    , kboIds
    , kboDetail
    , kboDiscMethod
    , kboAuthTypes
    , kboShowPciReasons
    , kboIsPatchable
    -- * Types
    , Vulnerability (..)
    , Software (..)
    , VendRef (..)
    , Compliance (..)
    , Exploit (..)
    , ExRef (..)
    , Malware (..)
    , MwInfo (..)
    , Cvss (..)
    , Discovery (..)
    ) where

import           Prelude hiding (mapM)
import           Control.Applicative hiding (many)
import           Control.Monad.Catch (MonadThrow (..))
import           Control.Monad.IO.Class (MonadIO)
import           Control.Monad.Trans.Class (lift)
import qualified Data.ByteString.Char8 as B8
import           Data.Conduit (($$), ConduitM)
import           Data.Maybe (fromMaybe)
import           Data.Monoid
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Time.Clock (UTCTime)
import           Data.Traversable (mapM)
import           Data.Typeable
import           Data.XML.Types
import           Network.HTTP.Client
import           Network.HTTP.Types (renderQuery)
import           Text.XML.Stream.Parse

import           Qualys.Internal
import           Qualys.Log
import           Qualys.V2api

-- * Options for the Qualys KnowledgeBase

-- | Get entries modified after this time
kboModAfter :: OptValTime a => a -> Param
kboModAfter x = ("last_modified_after",  toOptTm x)

-- | Get entries modified before this time
kboModBefore :: OptValTime a => a -> Param
kboModBefore x = ("last_modified_before",  toOptTm x)

-- | Get entries published after this time
kboPubAfter :: OptValTime a => a -> Param
kboPubAfter x = ("published_after", toOptTm x)

-- | Get entries published before this time
kboPubBefore :: OptValTime a => a -> Param
kboPubBefore x = ("published_before", toOptTm x)

-- | Get entries modified by a user after this time
kboUserModAfter :: OptValTime a => a -> Param
kboUserModAfter x = ("last_modified_by_user_after", toOptTm x)

-- | Get entries modified by a user before this time
kboUserModBefore :: OptValTime a => a -> Param
kboUserModBefore x = ("last_modified_by_user_before", toOptTm x)

-- | Get entries modified by the service after this time
kboServiceModAfter :: OptValTime a => a -> Param
kboServiceModAfter x  = ("last_modified_by_service_after", toOptTm x)

-- | Get entries modified by the service before this time
kboServiceModBefore :: OptValTime a => a -> Param
kboServiceModBefore x = ("last_modified_by_service_before", toOptTm x)

-- | Get QIDs greater to or equal this value
kboIdMin :: QID -> Param
kboIdMin x = ("id_min", toOptInt $ unQID x)

-- | Get QIDs less than or equal this value
kboIdMax :: QID -> Param
kboIdMax x = ("id_max", toOptInt $ unQID x)

-- | List of QIDs to retrieve
kboIds :: [QID] -> Param
kboIds xs  = ("ids", toOptList (toOptInt . unQID) xs)

-- | Detail level to Retrieve
kboDetail :: OptValText a => a -> Param
kboDetail x = ("details", toOptTxt x)

-- | Discovery Method
kboDiscMethod :: OptValText a => a -> Param
kboDiscMethod x = ("discovery_method", toOptTxt x)

-- | Retrieve vulnerabilities with these authentication types.
--   (Valid values are Windows, Oracle, Unix, and SNMP)
kboAuthTypes :: OptValText a => [a] -> Param
kboAuthTypes xs = ("discovery_auth_types" , toOptList toOptTxt xs)

-- | Include reasons for passing or failing PCI compliance by passing True.
kboShowPciReasons :: Bool -> Param
kboShowPciReasons x = ("show_pci_reasons", toOptBool x)

-- | Retrieve vulnerabilities that are patchable (True) or not patchable
--   (False).
kboIsPatchable :: Bool -> Param
kboIsPatchable x = ("show_pci_reasons", toOptBool x)

-- | A vulnerability from the KnowledgeBase. Some fields may not populate
--   depending on the options given and features in your Qualys subscription.
data Vulnerability = Vuln
    { kbQid      :: QID                -- ^ QID of the vulnerability
    , kbType     :: Text               -- ^ Type of vulnerability
    , kbSev      :: Int                -- ^ Severity
    , kbTitle    :: Text               -- ^ Name of the vulnerability
    , kbCat      :: Text               -- ^ Category (Web Application, etc.)
    , kbLastMod  :: Maybe UTCTime      -- ^ Last service modification
    , kbPublish  :: Maybe UTCTime      -- ^ Published date and time
    , kbBugTraq  :: Maybe [VendRef]    -- ^ BugTraq references
    , kbPatch    :: Bool               -- ^ Is the vulnerability patchable?
    , kbSoftware :: Maybe [Software]   -- ^ Software product information
    , kbVendRef  :: Maybe [VendRef]    -- ^ Vendor references
    , kbCVE      :: Maybe [VendRef]    -- ^ CVE(s) of the vulnerability
    , kbDiag     :: Maybe Text         -- ^ Diagnosis
    , kbDiagComm :: Maybe Text         -- ^ Diagnosis comment
    , kbCons     :: Maybe Text         -- ^ Consequence
    , kbConsComm :: Maybe Text         -- ^ Consequence comment
    , kbSolution :: Maybe Text         -- ^ Solution
    , kbSolComm  :: Maybe Text         -- ^ Solution comment
    , kbCompl    :: Maybe [Compliance] -- ^ Compliance information
    , kbExploits :: Maybe [Exploit]    -- ^ Exploit references
    , kbMalware  :: Maybe [Malware]    -- ^ Malware information
    , kbCvss     :: Maybe Cvss         -- ^ CVSS base score
    , kbPci      :: Bool               -- ^ Is this a PCI vulnerability?
    , kbPciReas  :: Maybe [Text]       -- ^ Why this passes/fails PCI compliance
    , kbDiscover :: Discovery          -- ^ Vulnerability discovery information
    } deriving (Show, Eq)

data Software = Software
    { swProduct :: Text
    , swVendor  :: Text
    } deriving (Show, Eq)

data VendRef = VendRef
    { vrId  :: Text
    , vrUrl :: Text
    } deriving (Show, Eq, Typeable)

data Compliance = Compliance
    { cmpType    :: Text -- ^ Type of compliance (e.g. HIPAA, SOX)
    , cmpSection :: Text -- ^ Section of policy or regulation
    , cmpDescr   :: Text -- ^ Description
    } deriving (Show, Eq)

data Exploit = Exploit
    { exSrcName :: Text    -- ^ Name of source
    , exploits  :: [ExRef] -- ^ References
    } deriving (Show, Eq)

data ExRef = ExRef
    { exrRef :: Text       -- ^ CVE reference
    , exDesc :: Text       -- ^ Description
    , exUrl  :: Maybe Text -- ^ URL of exploit if available
    } deriving (Show, Eq)

data Malware = Malware
    { mwSrcName :: Text     -- ^ Name of source (e.g. Trend Micro)
    , mwInfo    :: [MwInfo] -- ^ Malware information
    } deriving (Show, Eq)

data MwInfo = MwInfo
    { mwId       :: Text    -- ^ Malware name/id
    , mwType     :: Maybe Text -- ^ Type of malware (e.g. Backdoor)
    , mwPlatform :: Maybe Text -- ^ Platforms affected
    , mwAlias    :: Maybe Text -- ^ Other names used for this malware
    , mwRating   :: Maybe Text -- ^ Overall risk rating
    , mwUrl      :: Maybe Text -- ^ URL link to malware details
    } deriving (Show, Eq)

-- | CVSS data for a 'Vulnerability'. See \"CVSS V2 Sub Metrics Mapping\"
--   in Appendix A of the \"Qualys API V2 User Guide\" for meaning of the
--   'Int's.
data Cvss = Cvss
    { baseScore :: Maybe Int -- ^ Base score
    , tempScore :: Maybe Int -- ^ Temporal score
    , accVector :: Maybe Int -- ^ Access Vector
    , accCompl  :: Maybe Int -- ^ Access Complexity
    , impConf   :: Maybe Int -- ^ Confidentiality impact
    , impInteg  :: Maybe Int -- ^ Integrity impact
    , impAvail  :: Maybe Int -- ^ Availability impact
    , authed    :: Maybe Int -- ^ Authenticated
    , exploit   :: Maybe Int -- ^ Exploitability
    , remLevel  :: Maybe Int -- ^ Remediation level
    , repConf   :: Maybe Int -- ^ Report confidence
    } deriving (Show, Eq)

data Discovery = Discovery
    { remoteDisc :: Bool         -- ^ Remote Discoverable
    , authTypes  :: Maybe [Text] -- ^ Auth. types used
    } deriving (Show, Eq)

parseDoc :: (Monoid a, MonadThrow m) => (Vulnerability -> m a) ->
            ConduitM Event o m (Maybe V2Resp, a)
parseDoc = requireTagNoAttr "KNOWLEDGE_BASE_VULN_LIST_OUTPUT" . parseResp

parseResp :: (MonadThrow m, Monoid a) => (Vulnerability -> m a) ->
             ConduitM Event o m (Maybe V2Resp, a)
parseResp f = requireTagNoAttr "RESPONSE" $ do
    parseDiscard "DATETIME"
    vs <- parseVulns f
    w  <- parseWarning
    return (w,vs)

parseVulns :: (Monoid a, MonadThrow m) => (Vulnerability -> m a) ->
              ConduitM Event o m a
parseVulns f = do
    x <- tagNoAttr "VULN_LIST" $ many (parseVuln f)
    return . mconcat . fromMaybe [] $ x

parseCvssScore :: Integral a => Text -> Maybe a
parseCvssScore = parseBound 0 10

-- | Parse a vulnerability record, and write it to the database.
parseVuln :: (MonadThrow m) => (Vulnerability -> m a) ->
             ConduitM Event o m (Maybe a)
parseVuln f = mapM (lift . f) =<<
    tagNoAttr "VULN" (Vuln
        <$> (QID <$> requireWith parseUInt (tagNoAttr "QID" content))
        <*> requireTagNoAttr "VULN_TYPE" content
        <*> requireWith parseSev (tagNoAttr "SEVERITY_LEVEL" content)
        <*> requireTagNoAttr "TITLE" content
        <*> requireTagNoAttr "CATEGORY" content
        <*> (tagNoAttr "LAST_CUSTOMIZATION" (do
                parseDiscard "DATETIME"
                parseDiscard "USER_LOGIN")
            *> optionalWith parseDate
                (tagNoAttr "LAST_SERVICE_MODIFICATION_DATETIME" content))
        <*> optionalWith parseDate (tagNoAttr "PUBLISHED_DATETIME" content)
        <*> parseBugTraqList
        <*> requireWith parseBool (tagNoAttr "PATCHABLE" content)
        <*> parseSoftwareList
        <*> parseVendRefs
        <*> parseCVEs
        <*> tagNoAttr "DIAGNOSIS" content
        <*> tagNoAttr "DIAGNOSIS_COMMENT" content
        <*> tagNoAttr "CONSEQUENCE" content
        <*> tagNoAttr "CONSEQUENCE_COMMENT" content
        <*> tagNoAttr "SOLUTION" content
        <*> tagNoAttr "SOLUTION_COMMENT" content
        <*> parseComplianceList
        <*> optionalWith fst parseCorrelation
        <*> optionalWith snd parseCorrelation
        <*> parseCVSS
        <*> requireWith parseBool (tagNoAttr "PCI_FLAG" content)
        <*> tagNoAttr "PCI_REASONS" (many $ tagNoAttr "PCI_REASON" content)
        <*> parseDiscovery)

parseBugTraqList :: (MonadThrow m) => ConduitM Event o m (Maybe [VendRef])
parseBugTraqList = tagNoAttr "BUGTRAQ_LIST" $ many parseBugTraq

parseBugTraq :: (MonadThrow m) => ConduitM Event o m (Maybe VendRef)
parseBugTraq = tagNoAttr "BUGTRAQ" $ VendRef
    <$> requireTagNoAttr "ID" content
    <*> requireTagNoAttr "URL" content

parseSoftwareList :: (MonadThrow m) => ConduitM Event o m (Maybe [Software])
parseSoftwareList = tagNoAttr "SOFTWARE_LIST" $ many parseSoftware

parseSoftware :: (MonadThrow m) => ConduitM Event o m (Maybe Software)
parseSoftware = tagNoAttr "SOFTWARE" $ Software
    <$> requireTagNoAttr "PRODUCT" content
    <*> requireTagNoAttr "VENDOR" content

-- | Parse a CORRELATION, discarding the result
parseCorrelation :: (MonadThrow m) => ConduitM Event o m (Maybe (Maybe [Exploit],Maybe [Malware]))
parseCorrelation = tagNoAttr "CORRELATION" $ (,)
    <$> tagNoAttr "EXPLOITS" (many parseExpl)
    <*> tagNoAttr "MALWARE" (many parseMalware)

parseExpl :: (MonadThrow m) => ConduitM Event o m (Maybe Exploit)
parseExpl = tagNoAttr "EXPLT_SRC" $ Exploit
    <$> requireTagNoAttr "SRC_NAME" content
    <*> fmap (fromMaybe []) (tagNoAttr "EXPLT_LIST" $ many parseExRef)

parseExRef :: (MonadThrow m) => ConduitM Event o m (Maybe ExRef)
parseExRef = tagNoAttr "EXPLT" $ ExRef
    <$> requireTagNoAttr "REF" content
    <*> requireTagNoAttr "DESC" content
    <*> tagNoAttr "LINK" content

parseMalware :: (MonadThrow m) => ConduitM Event o m (Maybe Malware)
parseMalware = tagNoAttr "MW_SRC" $ Malware
    <$> requireTagNoAttr "SRC_NAME" content
    <*> fmap (fromMaybe []) (tagNoAttr "MW_LIST" $ many parseMwInfo)

parseMwInfo :: (MonadThrow m) => ConduitM Event o m (Maybe MwInfo)
parseMwInfo = tagNoAttr "MW_INFO" $ MwInfo
    <$> requireTagNoAttr "MW_ID" content
    <*> tagNoAttr "MW_TYPE" content
    <*> tagNoAttr "MW_PLATFORM" content
    <*> tagNoAttr "MW_ALIAS" content
    <*> tagNoAttr "MW_RATING" content
    <*> tagNoAttr "MW_LINK" content

parseCVSS :: (MonadThrow m) => ConduitM Event o m (Maybe Cvss)
parseCVSS = tagNoAttr "CVSS" $ do
    base <- tagName "BASE" (attr "source") (const content)
    temp <- tagNoAttr "TEMPORAL" content
    ac <- tagNoAttr "ACCESS" $ (,)
        <$> tagNoAttr "VECTOR" content
        <*> tagNoAttr "COMPLEXITY" content
    im <- tagNoAttr "IMPACT" $ (,,)
        <$> tagNoAttr "CONFIDENTIALITY" content
        <*> tagNoAttr "INTEGRITY" content
        <*> tagNoAttr "AVAILABILITY" content
    a <- tagNoAttr "AUTHENTICATION" content
    e <- tagNoAttr "EXPLOITABILITY" content
    rl <- tagNoAttr "REMEDIATION_LEVEL" content
    rc <- tagNoAttr "REPORT_CONFIDENCE" content
    return Cvss
        { baseScore = parseCvssScore =<< base
        , tempScore = parseCvssScore =<< temp
        , accVector = parseUInt =<< fst =<< ac
        , accCompl  = parseUInt =<< snd =<< ac
        , impConf   = parseUInt =<< fst' =<< im
        , impInteg  = parseUInt =<< snd' =<< im
        , impAvail  = parseUInt =<< thd' =<< im
        , authed    = parseUInt =<< a
        , exploit   = parseUInt =<< e
        , remLevel  = parseUInt =<< rl
        , repConf   = parseUInt =<< rc
        }
  where
    fst' (x,_,_) = x
    snd' (_,x,_) = x
    thd' (_,_,x) = x

parseVendRefs :: (MonadThrow m) => ConduitM Event o m (Maybe [VendRef])
parseVendRefs = tagNoAttr "VENDOR_REFERENCE_LIST" $ many parseVendRef

parseVendRef :: (MonadThrow m) => ConduitM Event o m (Maybe VendRef)
parseVendRef = tagNoAttr "VENDOR_REFERENCE" $ VendRef
    <$> requireTagNoAttr "ID" content
    <*> requireTagNoAttr "URL" content

-- | Parse CVEs
parseCVEs :: (MonadThrow m) => ConduitM Event o m (Maybe [VendRef])
parseCVEs = tagNoAttr "CVE_LIST" $ many parseCVE

parseCVE :: (MonadThrow m) => ConduitM Event o m (Maybe VendRef)
parseCVE = tagNoAttr "CVE" $ VendRef
    <$> requireTagNoAttr "ID" content
    <*> requireTagNoAttr "URL" content

parseComplianceList :: (MonadThrow m) => ConduitM Event o m (Maybe [Compliance])
parseComplianceList = tagNoAttr "COMPLIANCE_LIST" $ many parseCompliance

parseCompliance :: (MonadThrow m) => ConduitM Event o m (Maybe Compliance)
parseCompliance = tagNoAttr "COMPLIANCE" $ Compliance
    <$> requireTagNoAttr "TYPE" content
    <*> requireTagNoAttr "SECTION" content
    <*> requireTagNoAttr "DESCRIPTION" content

-- | Parse DISCOVERY
parseDiscovery :: (MonadThrow m) =>
                  ConduitM Event o m Discovery
parseDiscovery = requireTagNoAttr "DISCOVERY" $ Discovery
    <$> requireWith parseBool (tagNoAttr "REMOTE" content)
    <*> tagNoAttr "AUTH_TYPE_LIST" (many $ tagNoAttr "AUTH_TYPE" content)

getKbPage :: (Monoid a, MonadIO m, MonadThrow m) =>
             (Vulnerability -> QualysT m a) -> Maybe String ->
             QualysT m (Maybe V2Resp, a)
getKbPage _ Nothing = return (Nothing, mempty)
getKbPage f (Just uri) = do
    res <- fetchV2Get uri
    parseLBS def (responseBody res) $$ parseDoc f

-- | Keep requesting records until we've processed everything, or failed.
runKb :: (MonadIO m, MonadThrow m, Monoid a) =>
         (Vulnerability -> QualysT m a) -> Maybe String -> QualysT m a
runKb f uri = do
    (ret,xs) <- getKbPage f uri
    case ret of
        Nothing -> return xs
        Just r  -> case v2rCode r of
                    Just "1980" -> do
                        ys <- runKb f (T.unpack <$> v2rUrl r)
                        return $ ys <> xs
                    cd          -> do
                        qLog QLogError $
                            "Error from Qualys - Code: " <> T.pack (show cd) <>
                            " Message: " <> fromMaybe "" (v2rMsg r)
                        return xs

paramsToQuery :: [Param] -> String
paramsToQuery xs = B8.unpack . renderQuery True . fmap p2q $ uniqueParams xs
  where
    p2q (a,b) = (a,Just b)

-- | Run a function for each entry returned from the KnowledgeBase and
--   collect the results.
runKnowledgeBase :: (Monoid a, MonadIO m, MonadThrow m) =>
                    [Param] -> (Vulnerability -> QualysT m a) -> QualysT m a
runKnowledgeBase ps f = do
    let query = paramsToQuery $ [("action","list")] <> ps
--    let query = paramsToQuery $ ps
    base <- buildV2ApiUrl "knowledge_base/vuln/"
    runKb f (Just $ base <> query)

-- | Get entries from the KnowledgeBase.
getKnowledgeBase :: (MonadIO m, MonadThrow m) =>
                    [Param] -> QualysT m [Vulnerability]
getKnowledgeBase ps = runKnowledgeBase ps (\x -> return [x])
