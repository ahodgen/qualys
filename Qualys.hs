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
--  import Network.API.Qualys
--
--  myQualysConf :: QualysConf
--  myQualysConf = defaultQualysConf
--      { qcPlatform = qualysUSPlatform2
--      , qcUsername = "myusername"
--      , qcPassword = "mypassword"
--      }
--
--  main :: IO ()
--  main = do
--      withQualys myQualysConf $ do
--          xs <- getQualysKnowledgeBase defKnowledgeBaseOpts
--          print xs
-- @

module Qualys
    (
    -- * Functions
      withQualysT
    -- * Types
    , QualysT
    -- * Configuration
    , QualysConf (..)
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
    ) where

import Control.Monad.IO.Class (liftIO, MonadIO)
import Control.Monad.State (evalStateT)
import Network.HTTP.Client
import Network.HTTP.Client.TLS

import Qualys.Internal

import Qualys.KnowledgeBase
import Qualys.HostListDetection

-- | Given a 'QualysConf', run some action(s) against Qualys.
withQualysT :: MonadIO m => QualysConf -> QualysT m a -> m a
withQualysT c f = do
    manager <- liftIO $ newManager tlsManagerSettings
--    let sess = QualysSess c (createCookieJar []) manager qualysV2Auth noUnAuth
    evalStateT (unQualysT f) (sess manager)
  where
    sess m = QualysSess
        { qConf = c
        , qCookieJar = createCookieJar []
        , qManager   = m
        }
