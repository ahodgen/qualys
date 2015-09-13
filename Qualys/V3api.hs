{-# LANGUAGE OverloadedStrings, FlexibleInstances #-}
{-# OPTIONS_GHC -Wwarn #-}
module Qualys.V3api
    (
      V3Options (..)
    , V3Resp (..)
    , V3ErrDetail (..)
    , CritField (..)
      -- * Filters
    , equals
    , notEquals
    , lesser
    , greater
    , inList
    , contains
    , none
      -- * Low-level functions
      -- |
      -- This section contains functions for fetching results from the
      -- Qualys V3 API. You shouldn't need to use these unless you are extending
      -- the API or need low-level access.
    , buildV3ApiUrl
    , fetchV3
    , processV3With
    ) where

import           Control.Applicative
import           Control.Monad.IO.Class () -- MonadIO, liftIO) 
import           Control.Monad.Reader
import           Control.Monad.Trans.Resource (MonadThrow (..))
import qualified Data.ByteString.Lazy as BL
import           Data.Conduit (($$), ConduitM)
import qualified Data.Map as M
import           Data.Monoid ((<>))
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

data V3Resp = V3Resp
    { v3rCode    :: Text              -- ^ Response code
    , v3rErrDet  :: Maybe V3ErrDetail -- ^ Error details
    , v3rCount   :: Maybe Int         -- ^ Number of records in response
    , v3rMoreRec :: Maybe Bool        -- ^ More records?
    , v3rLastId  :: Maybe Int         -- ^ Last Id of records in response
    } deriving Show

data V3ErrDetail = V3ErrDetail
    { edMess    :: Text       -- ^ Error message
    , edResol   :: Maybe Text -- ^ Error resolution
    , edErrCode :: Maybe Int  -- ^ Qualys internal error code
    } deriving Show

data V3Options = V3Options
    { filt :: [Criteria]
    }

newtype CritField a = CF Text

data Criteria = Crit
    { field    :: Text
    , operator :: Text
    , criteria :: Text
    } deriving Show

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
            , elementAttributes = M.fromList [ ("field",    field x)
                                             , ("operator", operator x)
                                             ]
            , elementNodes = [NodeContent (criteria x)]
            }

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

class Equality a

instance Equality Text
instance Equality Int
instance Equality UTCTime
instance Equality Bool

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

equals :: (Equality a, RenderText a) => CritField a -> a -> Criteria
equals (CF lab) = Crit lab "EQUALS" . renTxt

notEquals :: (Equality a, RenderText a) => CritField a -> a -> Criteria
notEquals (CF lab) = Crit lab "NOT EQUALS" . renTxt

class Ordered a

instance Ordered Int
instance Ordered UTCTime

lesser :: (Ordered a, RenderText a) => CritField a -> a -> Criteria
lesser (CF lab) = Crit lab "LESSER" . renTxt

greater :: (Ordered a, RenderText a) => CritField a -> a -> Criteria
greater (CF lab) = Crit lab "GREATER" . renTxt

class InList a

instance InList Integer
-- instance InList Keyword

inList :: (InList a, RenderText a) => CritField a -> a -> Criteria
inList (CF lab) = Crit lab "IN" . renTxt

contains :: CritField Text -> Text -> Criteria
contains (CF lab) = Crit lab "CONTAINS"

none :: CritField () -> Criteria
none (CF lab) = Crit lab "NONE" ""

v3ApiPath :: String
v3ApiPath = "/qps/rest/3.0/"

buildV3ApiUrl :: MonadIO m => String -> QualysT m String
buildV3ApiUrl x = do
    sess <- liftReader ask
    return $ "https://" <> qualPlatform sess <> v3ApiPath <> x

-- XXX: How is rate-limiting done in V3? Couldn't find documentation.
fetchV3 :: (MonadIO m, MonadThrow m) => String -> Maybe V3Options ->
                        QualysT m (Response BL.ByteString)
fetchV3 p opt = do
    sess <- liftReader ask
    url <- buildV3ApiUrl p
    req <- liftIO $ parseUrl url
    let req' = req { method = v3meth
                   , requestHeaders = qualysHeaders
                   , responseTimeout = Just (1000000 * qualTimeout sess)
                   , requestBody = RequestBodyLBS (maybe "" v3OptXml opt)
                   }
    let req'' = applyBasicAuth (qualUser sess) (qualPass sess) req'
    liftIO $ httpLbs req'' (qManager sess)
  where
    v3meth = case opt of
                Nothing -> "GET"
                Just _  -> "POST"

-- | Given a path, options, and a function for parsing <data>,
--   fetch and parse via the V3 API. 
processV3With :: (MonadIO m, MonadThrow m)
              => String
              -> Maybe V3Options
              -> ConduitM Event Void (QualysT m) a
              -> QualysT m (V3Resp, Maybe a)
processV3With p opt f = do
    res <- fetchV3 p opt
    liftIO $ print res
    parseLBS def (responseBody res) $$ parseSvcResp f

parseSvcResp :: (MonadIO m, MonadThrow m) => ConduitM Event o m a ->
                        ConduitM Event o m (V3Resp, Maybe a)
parseSvcResp f = force "Blah"$ tagName "ServiceResponse" ignoreAttrs $ \_ -> (,)
    <$> (V3Resp
            <$> requireTagNoAttr "responseCode" content
            <*> tagNoAttr "responseErrorDetails" parseErrDetail
            <*> optionalWith parseUInt (tagNoAttr "count" content)
            <*> optionalWith parseBool (tagNoAttr "hasMoreRecords" content)
            <*> optionalWith parseUInt (tagNoAttr "lastId" content)
        )
    <*> tagNoAttr "data" f

parseErrDetail :: (MonadIO m, MonadThrow m) => ConduitM Event o m V3ErrDetail
parseErrDetail = V3ErrDetail
    <$> requireTagNoAttr "errorMessage" content
    <*> tagNoAttr "errorResolution" content
    <*> optionalWith parseUInt (tagNoAttr "internalErrorCodeId" content)