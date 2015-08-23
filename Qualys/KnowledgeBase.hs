{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wwarn #-}
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
    , VendRef (..)
    , Cvss (..)
    ) where

import           Control.Applicative hiding (many)
import           Control.Monad (join, void)
import           Control.Monad.IO.Class (liftIO, MonadIO)
import           Control.Monad.Trans.Class (lift)
import           Control.Monad.Trans.Resource (MonadThrow (..))
import qualified Data.ByteString.Char8 as B8
import           Data.Conduit (($$), ConduitM)
import           Data.Maybe (fromMaybe)
import           Data.Monoid
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Time.Clock (UTCTime)
import           Data.Time.Format (parseTime)
import           Data.XML.Types
import           Network.HTTP.Client
import           Network.HTTP.Types (renderQuery)
import           System.Locale (defaultTimeLocale)
import           Text.XML.Stream.Parse

import           Qualys.Core
import           Qualys.Util
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
kboIdMin :: (Integral a, Show a) => a -> Param
kboIdMin x = ("id_min", toOptInt x)

-- | Get QIDs less than or equal this value
kboIdMax :: (Integral a, Show a) => a -> Param
kboIdMax x = ("id_max", toOptInt x)

-- | List of QIDs to retrieve
kboIds :: (Integral a, Show a) => [a] -> Param
kboIds xs  = ("ids", toOptList toOptInt xs)

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

data Vulnerability = Vuln
    { kbQid      :: Int        -- ^ QID (Qualys ID) of the vulnerability
    , kbType     :: Text       -- ^ Type of vulnerability
    , kbPci      :: Bool       -- ^ Is this a PCI vulnerability?
    , kbPatch    :: Bool       -- ^ Is the vulnerability patchable?
    , kbCat      :: Text       -- ^ Category (Web Application, etc.)
    , kbSev      :: Int        -- ^ Severity (XXX:)
    , kbTitle    :: Text       -- ^ Name of the vulnerability
    , kbCVE      :: Maybe [Text] -- ^ CVE of the vulnerability
    , kbCvss     :: Maybe Cvss -- ^ CVSS base score
    , kbRemDisc  :: Bool       -- ^ Remote Discoverable
    , kbAuth     :: Maybe [Text] -- ^ Auth. types used
    , kbLastMod  :: Maybe UTCTime -- ^ Last service modification
    , kbPublish  :: Maybe UTCTime -- ^ Published date and time
    , kbVendRef  :: Maybe [VendRef] -- ^ Vendor reference URLs
    , kbSolution :: Maybe Text    -- ^ Solution
    , kbSolComm  :: Maybe Text    -- ^ Solution comment
    } deriving (Show, Eq)

data VendRef = VendRef
    { vrId  :: Maybe Text
    , vrUrl :: Maybe Text
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

parseDoc :: (Monoid a, MonadThrow m) => (Vulnerability -> m a) ->
            ConduitM Event o m (Maybe QualRet, a)
parseDoc f = force "No output!" .  tagNoAttr "KNOWLEDGE_BASE_VULN_LIST_OUTPUT" $
           parseResp f

parseResp :: (MonadThrow m, Monoid a) => (Vulnerability -> m a) ->
             ConduitM Event o m (Maybe QualRet,a)
parseResp f = force "No RESPONSE" . tagNoAttr "RESPONSE" $ do
    parseDiscard "DATETIME"
    vs <- parseVulns f
    w  <- parseWarning
    return (w,vs)

parseVulns :: (Monoid a, MonadThrow m) => (Vulnerability -> m a) -> ConduitM Event o m a
parseVulns f = do
    x <- tagNoAttr "VULN_LIST" $ many (parseVuln f)
    return $ mconcat $ fromMaybe [] x

parseCvssScore :: Integral a => Text -> Maybe a
parseCvssScore = parseBound 0 10

-- | Parse date/time
parseDate :: Text -> Maybe UTCTime
parseDate = parseTime defaultTimeLocale "%FT%T%QZ" . T.unpack

-- | Force a value with a parsing function.
forceWith :: (Text -> Maybe a) -> ConduitM Event o m (Maybe Text) ->
             ConduitM Event o m a
forceWith p i = do
    x <- i
    case join $ fmap p x of
        Nothing -> fail $ "Bad value '" <> show x <> "'"
        Just y  -> return y

-- | Parse a vulnerability record, and write it to the database.
parseVuln :: (MonadThrow m) => (Vulnerability -> m a) ->
             ConduitM Event o m (Maybe a)
parseVuln f = tagNoAttr "VULN" $ do
    q <- force "No QID!"       $ tagNoAttr "QID" content
    qid <- case parseUInt q of
                Nothing -> fail $ "Bad QID: " <> show q
                Just x  -> return x
    v <- force "No VULN_TYPE!" $ tagNoAttr "VULN_TYPE" content
    s <- forceWith parseSev    $ tagNoAttr "SEVERITY_LEVEL" content
    t <- force "No TITLE!"     $ tagNoAttr "TITLE" content
    c <- force "No category!"  $ tagNoAttr "CATEGORY" content
    _ <- tagNoAttr "LAST_CUSTOMIZATION" $ do
        parseDiscard "DATETIME"
        parseDiscard "USER_LOGIN"
    lm <- tagNoAttr "LAST_SERVICE_MODIFICATION_DATETIME" content
    pub <- tagNoAttr "PUBLISHED_DATETIME" content
    parseDiscList "BUGTRAQ_LIST" "BUGTRAQ" ["ID", "URL"]
    p <- forceWith parseBool   $ tagNoAttr "PATCHABLE" content
    parseDiscList "SOFTWARE_LIST" "SOFTWARE" ["PRODUCT", "VENDOR"]
    vends <- parseVendRefs
    cve <- parseCVEs
    parseDiscard "DIAGNOSIS"
    parseDiscard "DIAGNOSIS_COMMENT"
    parseDiscard "CONSEQUENCE"
    parseDiscard "CONSEQUENCE_COMMENT"
    sol <- tagNoAttr "SOLUTION" content
    slc <- tagNoAttr "SOLUTION_COMMENT" content
    parseDiscList "COMPLIANCE_LIST" "COMPLIANCE"
        ["TYPE", "SECTION", "DESCRIPTION"]
    parseCorrelation
    cvss <- parseCVSS'
    pc <- forceWith parseBool  $ tagNoAttr "PCI_FLAG" content
    parseDiscard "PCI_REASONS"
    disc <- parseDiscovery
    let (r,a) = fromMaybe (False,Nothing) disc
    let vuln = Vuln
            { kbQid  = qid
            , kbType = v
            , kbPci  = pc
            , kbPatch = p
            , kbCat   = c
            , kbSev   = s
            , kbTitle = t
            , kbCVE   = cve
            , kbCvss  = cvss
            , kbRemDisc  = r
            , kbAuth     = a
            , kbLastMod  = parseDate =<< lm
            , kbPublish  = parseDate =<< pub
            , kbVendRef  = vends
            , kbSolution = sol
            , kbSolComm  = slc
            }
    lift $ f vuln

-- | Parse a CORRELATION, discarding the result
parseCorrelation :: (MonadThrow m) => ConduitM Event o m ()
parseCorrelation = do
    _ <- tagNoAttr "CORRELATION" $ do
        _ <- tagNoAttr "EXPLOITS" $ many
            (tagNoAttr "EXPLT_SRC" $ do
                parseDiscard  "SRC_NAME"
                parseDiscList "EXPLT_LIST" "EXPLT" ["REF", "DESC", "LINK"]
            )
        _ <- tagNoAttr "MALWARE" $ many
            (tagNoAttr "MW_SRC" $ do
                parseDiscard  "SRC_NAME"
                parseDiscList "MW_LIST" "MW_INFO"
                    ["MW_ID", "MW_TYPE", "MW_PLATFORM", "MW_ALIAS"
                    , "MW_RATING", "MW_LINK"]
            )
        return ()
    return ()

parseCVSS' :: (MonadThrow m) => ConduitM Event o m (Maybe Cvss)
parseCVSS' = tagNoAttr "CVSS" $ do
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
    <$> tagNoAttr "ID" content
    <*> tagNoAttr "URL" content

-- | Parse CVEs
parseCVEs :: (MonadThrow m) => ConduitM Event o m (Maybe [Text])
parseCVEs = tagNoAttr "CVE_LIST" $ many parseCVE

parseCVE :: (MonadThrow m) => ConduitM Event o m (Maybe Text)
parseCVE = tagNoAttr "CVE" $ do
    i <- force "No CVE-ID found" $ tagNoAttr "ID" content
    parseDiscard "URL"
    return i

-- | Parse DISCOVERY
parseDiscovery :: (MonadThrow m) =>
                  ConduitM Event o m (Maybe (Bool, Maybe [Text]))
parseDiscovery = tagNoAttr "DISCOVERY" $ do
    r <- tagNoAttr "REMOTE" content
    a <- tagNoAttr "AUTH_TYPE_LIST" (many $ tagNoAttr "AUTH_TYPE" content)
    return (r == Just "1", a)

-- | Parse warnings/errors from Qualys.
parseWarning :: (MonadThrow m) => ConduitM Event o m (Maybe QualRet)
parseWarning = tagNoAttr "WARNING" $ QualRet
        <$> tagNoAttr "CODE" content
        <*> tagNoAttr "TEXT" content
        <*> tagNoAttr "URL"  content

-- | Ignore a Qualys-style list and all its elements.
--   Arguments are 1) List name 2) List items
--                 3) List of elements in the list item.
parseDiscList :: (MonadThrow m) => Name -> Name -> [Name] ->
                 ConduitM Event o m ()
parseDiscList list el vals = do
    _ <- tagNoAttr list $ many (tagNoAttr el $ mapM_ parseDiscard vals)
    return ()

-- | Convenience function for ignoring an element and content
parseDiscard :: (MonadThrow m) => Name -> ConduitM Event o m ()
parseDiscard x = void $ tagNoAttr x contentMaybe

getKbPage :: (Monoid a, MonadIO m, MonadThrow m) =>
             (Vulnerability -> QualysT m a) -> Maybe String ->
             QualysT m (Maybe QualRet, a)
getKbPage _ Nothing = return (Nothing, mempty)
getKbPage f (Just uri) = do
    res <- fetchQualysV2Get uri
    liftIO $ print res
    parseLBS def (responseBody res) $$ parseDoc f

-- | Keep requesting records until we've processed everything, or failed.
runKb :: (MonadIO m, MonadThrow m, Monoid a) =>
         (Vulnerability -> QualysT m a) -> Maybe String -> QualysT m a
runKb f uri = do
    (ret,xs) <- getKbPage f uri
    case ret of
        Nothing -> return xs
        Just r  -> case qrCode r of
                    Just "1980" -> do
                        ys <- runKb f (T.unpack <$> qrUrl r)
                        return $ ys <> xs
                    _           -> do
                        liftIO . print $ qrMsg r
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
