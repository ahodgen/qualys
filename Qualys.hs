{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module       : Network.API.Qualys
-- Copyright   : (c) 2015 Aaron Hodgen
--
-- License     : BSD-style
-- Maintainer  : ahodgen@kill-9.org
-- Stability   : experimental
-- Portability : GHC
--
-- A library for interacting with the <https://www.qualys.com Qualys> API.
-- It handles many of the low-level details such as paging, rate-limiting,
-- etc.
--
-- Example:
--
-- @
--  import Qualys
--
--  myQualysConf :: QualysConf
--  myQualysConf = defaultQualysConf
--      { qcPlatform = qualysUSPlatform2
--      , qcUsername = "myusername"
--      , qcPassword = "mypassword"
--      , qcTimeout  = 300
--      }
--
--  main :: IO ()
--  main = do
--      runQualysT myQualysConf $ do
--          xs <- getQualysKnowledgeBase []
--          print xs
-- @

module Qualys
    (
    -- * Functions
      runQualysT
    -- * Types
    , QualysT
    , QID (..)
    -- * Logging
    , Logger
    , QLogLevel
    , logDrop
    , logFd
    -- * Configuration
    , QualysConf (..)
    , defaultQualysConf
    -- ** Platform Configuation
    , QualysPlatform (..)
    , qualysUSPlatform1
    , qualysUSPlatform2
    , qualysEUPlatform
    , qualysPrivateCloudPlatform
    -- * API Actions
    -- | For examples of using APIs, see "Qualys.Cookbook".
    , module Qualys.KnowledgeBase
    , module Qualys.HostListDetection
    , module Qualys.WasScan
    , module Qualys.WasWebApp
    ) where

import Control.Monad.IO.Class (liftIO, MonadIO)
import Control.Monad.Reader (runReaderT)
import Network.HTTP.Client
import Network.HTTP.Client.TLS

import Qualys.Internal
import Qualys.Log

import Qualys.KnowledgeBase
import Qualys.HostListDetection
import Qualys.WasScan
import Qualys.WasWebApp

-- | Default QualysConf
defaultQualysConf :: QualysConf
defaultQualysConf = QualysConf
    { qcPlatform = qualysUSPlatform1
    , qcUsername = ""
    , qcPassword = ""
    , qcTimeOut  = 300
    , qcRetries  = 5
    , qcLogger   = logStderr
    }

-- | Given a 'QualysConf' run some action(s) against Qualys.
runQualysT :: MonadIO m => QualysConf -> QualysT m a -> m a
runQualysT c f = do
    manager <- liftIO $ newManager tlsManagerSettings
    runReaderT (unQualysT f) (sess manager)
  where
    sess m = QualysSess
        { qConf = c
        , qManager   = m
        }
