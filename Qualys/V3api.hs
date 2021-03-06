{-# LANGUAGE OverloadedStrings, FlexibleInstances #-}
{-# OPTIONS_GHC -Wwarn #-}
-- | Qualys V3 API Handling
module Qualys.V3api
    (
      -- * Types
      V3Options (..)
    , V3Resp (..)
    , V3ErrDetail (..)
    , V3Vers (..)
    , CritField (..)
      -- * Filter Operations
    , equals
    , notEquals
    , lesser
    , greater
    , inList
    , contains
    , none
      -- * Low-level functions
      -- |
      -- This section contains low-level functions for the V3 API.
      -- You shouldn't need these unless you are extending this library or
      -- need low-level access.
    , buildV3ApiUrl
    , fetchV3
    , processV3With
    , processV3PageWith
    ) where

import           Control.Applicative
import           Control.Monad.Catch (MonadThrow (..))
import           Control.Monad.IO.Class ()
import           Control.Monad.Reader
import           Control.Retry
import qualified Data.ByteString.Lazy as BL
import           Data.Conduit (($$), ConduitM)
import qualified Data.Map as M
import           Data.Maybe (fromMaybe)
import           Data.Monoid ((<>), Monoid)
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Time.Clock (UTCTime)
import           Data.Time.Format (formatTime)
import           Data.Void (Void)
import           Data.XML.Types (Event)
import           Network.HTTP.Client
import           System.Locale (defaultTimeLocale)
import           Text.XML hiding (parseLBS)
import           Text.XML.Stream.Parse

import Qualys.Internal
import Qualys.Log

-- | V3 response from Qualys
data V3Resp = V3Resp
    { v3rCode    :: Text              -- ^ Response code
    , v3rErrDet  :: Maybe V3ErrDetail -- ^ Error details
    , v3rCount   :: Maybe Int         -- ^ Number of records in response
    , v3rMoreRec :: Maybe Bool        -- ^ More records?
    , v3rLastId  :: Maybe Int         -- ^ Last Id of records in response
    } deriving Show

-- | Error Details
data V3ErrDetail = V3ErrDetail
    { edMess    :: Text       -- ^ Error message
    , edResol   :: Maybe Text -- ^ Error resolution
    , edErrCode :: Maybe Int  -- ^ Qualys internal error code
    } deriving Show

-- | V3 API options
data V3Options = V3Options
    { filt :: [Criteria] -- ^ Filters
    } deriving Show

-- | Criteria field. It contains the textual representation of the option
-- and a phantom type @a@ to indicate what type of value it expects.
newtype CritField a = CF Text

-- | Filter criteria.
data Criteria = Crit
    { field :: Text      -- ^ Qualys field name (usually listed under \"Input\"
                         --   in the API docs).
    , oper  :: Operation -- ^ Operator
    , value :: Text      -- ^ Text representation of the value
    } deriving Show

-- | Filter operations
data Operation = Equals
               | NotEquals
               | Lesser
               | Greater
               | InList
               | Contains
               | None
               deriving Eq

instance Show Operation where
    show Equals    = "EQUALS"
    show NotEquals = "NOT EQUALS"
    show Lesser    = "LESSER"
    show Greater   = "GREATER"
    show InList    = "IN"
    show Contains  = "CONTAINS"
    show None      = "NONE"

-- | Render 'Criteria' to XML.
critToXml :: [Criteria] -> [Node]
critToXml [] = []
critToXml xs =
    [NodeElement Element
        { elementName = "filters"
        , elementAttributes = M.empty
        , elementNodes = fmap toCrit xs
        }
    ]
  where
    toCrit x =
        NodeElement Element
            { elementName = "Criteria"
            , elementAttributes = M.fromList
                [ ("field",    field x)
                , ("operator", (T.pack . show . oper) x)
                ]
            , elementNodes = [NodeContent (value x)]
            }

-- | Turn options into an XML ByteString
v3OptXml :: V3Options -> BL.ByteString
v3OptXml x = renderLBS def Document
    { documentPrologue = Prologue [] Nothing []
    , documentRoot     = renderNodes
    , documentEpilogue = []
    }
  where
    renderNodes =
        Element
            { elementName = "ServiceRequest"
            , elementAttributes = M.empty
            , elementNodes = critToXml (filt x)
            }

-- | Class for converting filter values to Text suitable for Qualys.
class RenderText a where
    renTxt :: a -> Text

instance RenderText Text where
    renTxt = id

instance RenderText Int where
    renTxt = T.pack . show

instance RenderText UTCTime where
    renTxt = T.pack . formatTime defaultTimeLocale "%FT%TZ"

instance RenderText Bool where
    renTxt True  = "true"
    renTxt False = "false"

-- | Class for equality operations on filters
class Equality a

instance Equality Text
instance Equality Int
instance Equality UTCTime
instance Equality Bool

-- | Test if the field equals the value.
equals :: (Equality a, RenderText a) => CritField a -> a -> Criteria
equals (CF lab) = Crit lab Equals . renTxt

-- | Test if the field does not equal the value.
notEquals :: (Equality a, RenderText a) => CritField a -> a -> Criteria
notEquals (CF lab) = Crit lab NotEquals . renTxt

-- | Class for ordered operations on filters
class Ordered a

instance Ordered Int
instance Ordered UTCTime

-- | Test if the field is less than the value.
lesser :: (Ordered a, RenderText a) => CritField a -> a -> Criteria
lesser (CF lab) = Crit lab Lesser . renTxt

-- | Test if the field is greater than the value.
greater :: (Ordered a, RenderText a) => CritField a -> a -> Criteria
greater (CF lab) = Crit lab Greater . renTxt

-- | Class for list membership.
class InList a

instance InList Int

-- | Test if the field contains a value in the list.
inList :: (InList a, RenderText a) => CritField a -> a -> Criteria
inList (CF lab) = Crit lab InList . renTxt

-- | Test if the field contains the value.
contains :: CritField Text -> Text -> Criteria
contains (CF lab) = Crit lab Contains

-- | Test if the field contains no data.
none :: CritField () -> Criteria
none (CF lab) = Crit lab None ""

-- | Paging
v3NextPage :: Maybe V3Options -> V3Resp -> Maybe V3Options
v3NextPage mopt resp =
    case v3rMoreRec resp of
        Just True -> case v3rLastId resp of
            Just x  -> Just $ addFilt x
            Nothing -> mopt
        _         -> mopt
  where
    -- Add a filter to get the next page
    addFilt x = V3Options { filt = next x : rgt }
    -- Get entries with ID greater than the returned min id
    next x = (CF "id" :: CritField Int) `greater` x
    -- Remove filter for "greater than id" so there is no conflict
    rgt = filter gtId cr
    gtId x = field x == "id" && oper x == Greater
    -- Get the current filters, or [] if non-existent
    cr  = filt $ fromMaybe (V3Options []) mopt

-- | Base path for the V3 API.
v3ApiPath :: String
v3ApiPath = "/qps/rest/"

-- | Version of V3 API
data V3Vers = V3v20 | V3v30

instance Show V3Vers where
    show V3v20 = "2.0"
    show V3v30 = "3.0"

-- | Build a V3 URL given a relative path under the base path.
buildV3ApiUrl :: MonadIO m => V3Vers -> String -> QualysT m String
buildV3ApiUrl v x = do
    sess <- liftReader ask
    return $ "https://" <> qualPlatform sess <> v3ApiPath <> show v <> "/" <> x

-- | Given a relative path and options, send a request and return the
-- response from Qualys.
fetchV3 :: (MonadIO m, MonadThrow m) => V3Vers -> String -> Maybe V3Options ->
                        QualysT m (Response BL.ByteString)
-- XXX: How is rate-limiting done in V3? Couldn't find documentation.
fetchV3 v p opt = do
    sess <- liftReader ask
    url <- buildV3ApiUrl v p
    req <- liftIO $ parseUrl url
    let req' = req { method = v3meth
                   , requestHeaders = qualysHeaders
                   , responseTimeout = Just (1000000 * qualTimeout sess)
                   , requestBody = RequestBodyLBS (maybe "" v3OptXml opt)
                   }
    let req'' = applyBasicAuth (qualUser sess) (qualPass sess) req'
    qLog QLogDebug . T.pack $ "fetchV3 (" <> show v3meth <> "): " <> url <>
                              " opts: " <> show opt
    res <- liftIO . recoverAll (retryStrat sess) . const $ httpLbs req'' (qManager sess)
    qLog QLogDebug "DONE FETCH"
    return res
  where
    v3meth = case opt of
                Nothing -> "GET"
                Just _  -> "POST"

-- | Given a path, options, and a function for parsing <data>,
--   fetch and parse via the V3 API. 
processV3With :: (MonadIO m, MonadThrow m)
              => V3Vers
              -> String
              -> Maybe V3Options
              -> ConduitM Event Void (QualysT m) a
              -> QualysT m (V3Resp, Maybe a)
processV3With v p opt f = do
    res <- fetchV3 v p opt
    parseLBS def (responseBody res) $$ parseSvcResp f

-- | Given a path, options, and a function for parsing <data>,
--   fetch and parse via the V3 API that may contain paged results
processV3PageWith :: (MonadIO m, MonadThrow m, Monoid a)
                  => V3Vers
                  -> String
                  -> Maybe V3Options
                  -> ConduitM Event Void (QualysT m) a
                  -> QualysT m (V3Resp, Maybe a)
processV3PageWith v p opt f = do
    res <- fetchV3 v p opt
    (r,x) <- parseLBS def (responseBody res) $$ parseSvcResp f
    case v3rMoreRec r of
        Just True -> do
            (r',x') <- processV3With v p (v3NextPage opt r) f
            return (r', x <> x')
        _         -> return (r,x)

-- | Parse the base ServiceResponse, and pass the <data> section to 'f' for
-- further parsing.
parseSvcResp :: (MonadIO m, MonadThrow m) => ConduitM Event o m a ->
                        ConduitM Event o m (V3Resp, Maybe a)
parseSvcResp f = force "ServiceResponse"$
    tagName "ServiceResponse" ignoreAttrs $ \_ -> (,)
        <$> (V3Resp
            <$> requireTagNoAttr "responseCode" content
            <*> tagNoAttr "responseErrorDetails" parseErrDetail
            <*> optionalWith parseUInt (tagNoAttr "count" content)
            <*> optionalWith parseBool (tagNoAttr "hasMoreRecords" content)
            <*> optionalWith parseUInt (tagNoAttr "lastId" content)
            )
        <*> tagNoAttr "data" f

-- | Parse the error detail
parseErrDetail :: (MonadIO m, MonadThrow m) => ConduitM Event o m V3ErrDetail
parseErrDetail = V3ErrDetail
    <$> requireTagNoAttr "errorMessage" content
    <*> tagNoAttr "errorResolution" content
    <*> optionalWith parseUInt (tagNoAttr "internalErrorCodeId" content)
