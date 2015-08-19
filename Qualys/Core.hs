{-# LANGUAGE OverloadedStrings, FlexibleContexts #-}

module Qualys.Core
    ( QualysConf(..)
    , QualysSess(..)
    , qualysHeaders
    , QualysPlatform (..)
    , qualysUSPlatform1
    , qualysUSPlatform2
    , qualysEUPlatform
    , qualysPrivateCloudPlatform
    , QualysT
    , Qualys
    ) where

import Prelude
-- import Control.Monad.IO.Class (MonadIO(..)) -- , liftIO)
-- import Control.Monad.Trans (liftIO, MonadIO)
-- import Control.Monad.Trans.Control (MonadBaseControl)
-- import Control.Monad.Trans.Resource (MonadThrow)
import Control.Monad.State
import qualified Data.ByteString as B
import Data.Monoid ((<>))
import Network.HTTP.Client
-- import Network.HTTP.Client.TLS
import Network.HTTP.Types.Header (HeaderName)

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
-- create a QualysPlatform with "qualysapi." prepended.
qualysPrivateCloudPlatform :: String -> QualysPlatform
qualysPrivateCloudPlatform = QualysPlatform . (<>) "qualysapi."

qualysHeaders :: [(HeaderName, B.ByteString)]
qualysHeaders = [ ("User-Agent",       "NCSA_Mosaic/2.0" )
                , ("X-Requested-With", "Shrubbery" )
                , ("Content-Type",     "text/xml")
                ]

data QualysConf = QualysConf
    { qcPlatform :: QualysPlatform -- ^ Qualys Platform to use
    , qcUsername :: B.ByteString   -- ^ Qualys Username
    , qcPassword :: B.ByteString   -- ^ Qualys Password
    , qcTimeOut  :: Int            -- ^ Timeout (in seconds)
    } deriving Show

data QualysSess = QualysSess
                { qConf      :: QualysConf -- ^ Qualys Configuration
                , qCookieJar :: CookieJar  -- ^ Cookie Jar
                , qManager   :: Manager    -- ^ HTTP Manager
                }
type QualysT m a = StateT QualysSess m a

type Qualys a = QualysT IO a
