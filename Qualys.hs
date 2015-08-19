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
    ( withQualysT
    , withQualys
    , test
    ) where

import Control.Monad.IO.Class (liftIO, MonadIO)
import Control.Monad.State (evalStateT)
import Network.HTTP.Client
import Network.HTTP.Client.TLS

import Qualys.Core

myConf :: QualysConf
myConf = QualysConf
      { qcPlatform = qualysUSPlatform2
      , qcUsername = "myusername"
      , qcPassword = "mypassword"
      , qcTimeOut  = 300
      }

test :: IO ()
test =
    withQualysT myConf $
        liftIO $ putStrLn "HELLO"

withQualysT :: MonadIO m => QualysConf -> QualysT m a -> m a
withQualysT c f = do
    manager <- liftIO $ newManager tlsManagerSettings
--    let sess = QualysSess c (createCookieJar []) manager qualysV2Auth noUnAuth
    evalStateT f (sess manager)
  where
    sess m = QualysSess
        { qConf = c
        , qCookieJar = createCookieJar []
        , qManager   = m
        }

withQualys :: QualysConf -> Qualys a -> IO a
withQualys = withQualysT
