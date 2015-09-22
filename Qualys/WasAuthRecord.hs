{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wwarn #-}
-- | For practical examples see "Qualys.Cookbook.WasAuthRecord".
module Qualys.WasAuthRecord
    (
    -- * Actions
      getWasAuthRecCount
    , runWasSearchAuthRec
    , getWasAuthRecDetail
    -- * Filters
    ) where

import           Control.Monad (join)
import           Data.Monoid ((<>))

import           Qualys.Internal
import           Qualys.Internal.ParseWasAuthRec
import           Qualys.V3api
import           Qualys.Types.Was

getWasAuthRecCount :: QualysT IO (Maybe Int)
getWasAuthRecCount = do
    res <- processV3With "count/was/webappauthrecord" Nothing (return ())
    return . v3rCount . fst $ res

runWasSearchAuthRec :: Maybe V3Options -> QualysT IO (Maybe [WsAuthRec])
runWasSearchAuthRec opt = do
    res <- processV3With "search/was/webappauthrecord" opt parseAuthRecs
    return . snd $ res

getWasAuthRecDetail :: Int -> QualysT IO (Maybe WsAuthRec)
getWasAuthRecDetail x = do
    res <- processV3With ("get/was/webappauthrecord/" <> show x) Nothing parseAuthRec
    return . join . snd $ res
