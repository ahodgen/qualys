{-# LANGUAGE OverloadedStrings, GeneralizedNewtypeDeriving #-}
-- | Internal functions intended only to be used by this package. API stability
--   not guaranteed!
module Qualys.Internal where

import           Control.Applicative
import           Control.Monad.State
import           Control.Monad.Trans.Resource (MonadThrow (..))
import qualified Data.ByteString as B
import           Data.Monoid ((<>))
import           Network.HTTP.Client
import Network.HTTP.Types.Header (HeaderName)

-- | Qualys transformer, which carries around a session and returns an @a@.
newtype QualysT m a = QualysT { unQualysT :: StateT QualysSess m a}
                      deriving (Functor, Applicative, Monad)

instance MonadIO m => MonadIO (QualysT m) where
  liftIO = QualysT . liftIO

instance MonadThrow m => MonadThrow (QualysT m) where
    throwM = lift . throwM

instance MonadTrans QualysT where
  lift = QualysT . lift

liftState :: Monad m => StateT QualysSess m a -> QualysT m a
liftState = QualysT

-- | Qualys Configuration
data QualysConf = QualysConf
    { qcPlatform :: QualysPlatform -- ^ Qualys Platform to use
    , qcUsername :: B.ByteString   -- ^ Qualys Username
    , qcPassword :: B.ByteString   -- ^ Qualys Password
    , qcTimeOut  :: Int            -- ^ Timeout (in seconds)
    } deriving Show

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

qualysHeaders :: [(HeaderName, B.ByteString)]
qualysHeaders = [ ("User-Agent",       "NCSA_Mosaic/2.0" )
                , ("X-Requested-With", "Shrubbery" )
                , ("Content-Type",     "text/xml")
                ]

data QualysSess = QualysSess
                { qConf      :: QualysConf -- ^ Qualys Configuration
                , qCookieJar :: CookieJar  -- ^ Cookie Jar
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
