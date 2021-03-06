{-# LANGUAGE OverloadedStrings, GeneralizedNewtypeDeriving, RankNTypes,
             DeriveDataTypeable #-}
-- | Internal functions intended only to be used by this package. API stability
--   not guaranteed!
module Qualys.Internal
    (
      QualysT (..)
    , QID (..)
    , liftReader
    -- * Logging
    , QLogLevel (..)
    , Logger
    -- * Configuration
    , QualysConf (..)
    , QualysPlatform (..)
    , qualysUSPlatform1
    , qualysUSPlatform2
    , qualysEUPlatform
    , qualysPrivateCloudPlatform
    , retryStrat
    -- * Session data
    , QualysSess (..)
    , qualysHeaders
    , qualTimeout
    , qualUser
    , qualPass
    , qualPlatform
    , qualLogger
    , qualRetries
    -- * Convenience functions for XML processing
    , parseBool
    , parseUInt
    , parseBound
    , parseSev
    , parseDate
    , requireTagNoAttr
    , requireWith
    , optionalWith
    , parseDiscard
    )where

import           Control.Applicative
import           Control.Monad.Reader
import           Control.Monad.Catch
import           Control.Retry
import qualified Data.ByteString as B
import           Data.Conduit (ConduitM)
import           Data.Monoid ((<>))
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Read as T
import           Data.Time.Clock  (UTCTime)
import           Data.Time.Format (parseTime)
import           Data.Typeable
import           Data.XML.Types
import           Network.HTTP.Client
import           Network.HTTP.Types.Header (HeaderName)
import           System.Locale (defaultTimeLocale)
import           Text.XML.Stream.Parse

-- | Qualys transformer, which carries around a session and returns an @a@.
newtype QualysT m a = QualysT { unQualysT :: ReaderT QualysSess m a}
                      deriving (Functor, Applicative, Monad)

instance MonadIO m => MonadIO (QualysT m) where
  liftIO = QualysT . liftIO

instance MonadThrow m => MonadThrow (QualysT m) where
    throwM = lift . throwM

instance MonadCatch m => MonadCatch (QualysT m) where
    catch (QualysT x) handler = QualysT $ catch x (unQualysT . handler)

instance MonadMask m => MonadMask (QualysT m) where
    mask x = QualysT $ mask $ \y -> unQualysT $ x (QualysT . y . unQualysT)
    uninterruptibleMask x = QualysT $ uninterruptibleMask $ \y -> unQualysT $ x (QualysT . y . unQualysT)

instance MonadTrans QualysT where
  lift = QualysT . lift

newtype QID = QID { unQID :: Int } deriving (Show, Eq, Ord, Typeable)

-- | Lifts an action that works on @ReaderT@ to one that works on
-- @QualysT@.
liftReader :: Monad m => ReaderT QualysSess m a -> QualysT m a
liftReader = QualysT

type Logger m = QLogLevel -> Text -> m ()

data QLogLevel = QLogDebug
               | QLogWarn
               | QLogError
               deriving (Eq, Ord, Show)

-- | Qualys Configuration
data QualysConf = QualysConf
    { qcPlatform :: QualysPlatform -- ^ Qualys Platform to use
    , qcUsername :: B.ByteString   -- ^ Qualys Username
    , qcPassword :: B.ByteString   -- ^ Qualys Password
    , qcTimeOut  :: Int            -- ^ Timeout (in seconds)
    , qcRetries  :: Int            -- ^ Number of retries
    , qcLogger   :: forall m.(MonadIO m) => Logger m -- ^ Function to log
    } -- deriving Show

-- | Qualys platform to send requests to.
newtype QualysPlatform = QualysPlatform { unQualysPlatform :: String }
    deriving Show

-- | Qualys US Platform 1
qualysUSPlatform1 :: QualysPlatform
qualysUSPlatform1 = QualysPlatform "qualysapi.qualys.com"

-- | Qualys US Platform 2
qualysUSPlatform2 :: QualysPlatform
qualysUSPlatform2 = QualysPlatform "qualysapi.qg2.apps.qualys.com"

-- | Qualys EU Platform
qualysEUPlatform :: QualysPlatform
qualysEUPlatform = QualysPlatform "qualysapi.qualys.eu"

-- | Qualys Private Cloud Platform. Given a string, this function will
-- create a @QualysPlatform@ with "qualysapi." prepended.
qualysPrivateCloudPlatform :: String -> QualysPlatform
qualysPrivateCloudPlatform = QualysPlatform . (<>) "qualysapi."

-- | Required Qualys headers
qualysHeaders :: [(HeaderName, B.ByteString)]
qualysHeaders = [ ("User-Agent",       "Qualys/Haskell" )
                , ("X-Requested-With", "Irrelevant" )
                , ("Content-Type",     "text/xml")
                ]

-- | Qualys session. Contains configuation and @Manager@.
data QualysSess = QualysSess
                { qConf      :: QualysConf -- ^ Qualys Configuration
                , qManager   :: Manager    -- ^ HTTP Manager
                }

-- | Reach into a @QualysSess@ and grab the timeout
qualTimeout :: QualysSess -> Int
qualTimeout = qcTimeOut . qConf

-- | Get the username from a @QualysSess@.
qualUser :: QualysSess -> B.ByteString
qualUser = qcUsername . qConf

-- | Get the password from a @QualysSess@.
qualPass :: QualysSess -> B.ByteString
qualPass = qcPassword . qConf

-- | Grab the platform from a @QualysSess@.
qualPlatform:: QualysSess -> String
qualPlatform = unQualysPlatform . qcPlatform . qConf

-- | Grab the logger from a @QualysSess@.
qualLogger :: (MonadIO m) => QualysSess -> Logger m
qualLogger = qcLogger . qConf

-- | Get the number of retries from a @QualysSess@.
qualRetries :: QualysSess -> Int
qualRetries = qcRetries . qConf

-- | Retry Strategy - 5 seconds with exponential backoff
retryStrat :: Monad m => QualysSess -> RetryPolicyM m
retryStrat sess = exponentialBackoff 5000000 <> limitRetries (qualRetries sess)

-- | Parse a text into a Bool.
parseBool :: Text -> Maybe Bool
parseBool "0"     = Just False
parseBool "false" = Just False
parseBool "1"     = Just True
parseBool "true"  = Just True
parseBool _   = Nothing

-- | Parse text into an unsigned integral.
parseUInt :: Integral a => Text -> Maybe a
parseUInt x = case T.decimal x of
    Right (n,"") -> Just n
    _            -> Nothing

-- | Parse text to an int bound by a min and max.
parseBound :: Integral a => a -> a -> Text -> Maybe a
parseBound mn mx x = check =<< parseUInt x
  where
    check n
        | n >= mn && n <= mx = Just n
        | otherwise          = Nothing

-- | Parse a text value into a severity, enforcing the correct range.
parseSev :: Integral a => Text -> Maybe a
parseSev = parseBound 0 5

-- | Parse a text value into UTCTime
parseDate :: Text -> Maybe UTCTime
parseDate = parseTime defaultTimeLocale "%FT%T%QZ" . T.unpack

-- | Require a tag with no attributes set.
requireTagNoAttr :: (MonadThrow m) => Name -> ConduitM Event o m a ->
                    ConduitM Event o m a
requireTagNoAttr x = force err . tagNoAttr x
  where
    err = "Tag '" <> show x <> "' required!"

-- | Required value with a parsing function.
requireWith :: Show a => (a -> Maybe b) -> ConduitM Event o m (Maybe a) ->
               ConduitM Event o m b
requireWith p i = do
    x <- i
    case join (fmap p x) of
        Nothing -> fail $ "Bad value '" <> show x <> "'"
        Just y  -> return y

-- | Optional value with a parsing function.
optionalWith :: MonadThrow m => (a -> Maybe b) ->
                ConduitM Event o m (Maybe a) -> ConduitM Event o m (Maybe b)
optionalWith f v = do
    x <- v
    return $ f =<< x

-- | Convenience function for ignoring an element and content
parseDiscard :: (MonadThrow m) => Name -> ConduitM Event o m ()
parseDiscard x = void $ tagNoAttr x contentMaybe
