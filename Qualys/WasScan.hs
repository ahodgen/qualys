{-# LANGUAGE OverloadedStrings, RankNTypes #-}
{-# OPTIONS_GHC -Wwarn #-}
-- | For practical examples see "Qualys.Cookbook.WasSearchScans".
module Qualys.WasScan
    (
    -- * Actions
      getWasScanCount
    , runWasSearchScans
    , getWasScanDetail
    , getWasScanStatus
    , getWasScanResult
    -- * Filters
    -- ** WasScan Search Filters
    , wssFiltId
    , wssFiltName
    , wssFiltWebAppName
    , wssFiltWebAppId
    , wssFiltWebAppTags
    , wssFiltWebAppTagsId
    , wssFiltReference
    , wssFiltLaunchedDate
    , wssFiltType
    , wssFiltMode
    , wssFiltStatus
    , wssFiltAuthStatus
    , wssFiltResultsStatus
    -- * Types
    , WasScan (..)
    , WsScanProfile (..)
    , WsTarget (..)
    , WsWebApp (..)
    , WsTag (..)
    , WsAuthRec (..)
    , WsProxy (..)
    , WsUser (..)
    , WsSummary (..)
    , WsStat (..)
    , WsGlobalStat (..)
    , WsNameStat (..)
    , WsScanResult (..)
    , WsInstance (..)
    , WsPayload (..)
    , WsIg (..)
    ) where

import           Control.Monad (join)
import           Control.Monad.Catch (MonadThrow)
import           Control.Monad.IO.Class (MonadIO)
import           Data.Conduit (($$))
import           Data.Monoid ((<>))
import           Data.Text (Text)
import           Data.Time.Clock (UTCTime)
import           Network.HTTP.Client hiding (Proxy)
import           Text.XML.Stream.Parse

import           Qualys.Internal
import           Qualys.Internal.ParseWasScan
import           Qualys.V3api
import           Qualys.Types.Was

-- | Filter by scan ID.
wssFiltId :: CritField Int
wssFiltId = CF "id"

-- | Filter by scan name.
wssFiltName :: CritField Text
wssFiltName = CF "name"

-- | Filter by web application name.
wssFiltWebAppName :: CritField Text
wssFiltWebAppName = CF "webApp.name"

-- | Filter by web application ID.
wssFiltWebAppId :: CritField Int
wssFiltWebAppId = CF "webApp.id"

-- | Filter if no tags.
wssFiltWebAppTags :: CritField ()
wssFiltWebAppTags = CF "webApp.tags"

-- | Filter by tag ID.
wssFiltWebAppTagsId :: CritField Int
wssFiltWebAppTagsId = CF "webApp.tags.id"

-- | Filter by scan reference
wssFiltReference :: CritField Text
wssFiltReference = CF "reference"

-- | Filter by scan launch date/time.
wssFiltLaunchedDate :: CritField UTCTime
wssFiltLaunchedDate = CF "launchedDate"

-- | Filter by type (VULNERABILITY or DISCOVERY).
wssFiltType :: CritField Text
wssFiltType = CF "type"

-- | Filter by mode (ONDEMAND, SCHEDULED, API).
wssFiltMode :: CritField Text
wssFiltMode = CF "mode"

-- | Filter by status (SUBMITTED, RUNNING, FINISHED, ERROR, CANCELLED).
wssFiltStatus :: CritField Text
wssFiltStatus = CF "status"

-- | Filter by auth status (NONE, NOT_USED, SUCCESSFUL, FAILED, PARTIAL).
wssFiltAuthStatus :: CritField Text
wssFiltAuthStatus = CF "authStatus"

-- | Filter by results status (NOT_USED, TO_BE_PROCESSED, NO_HOST_ALIVE,
--   NO_WEB_SERVICE, TIME_LIMIT_EXCEEDED, SCAN_RESULTS_INVALID, SUCCESSFUL,
--   PROCESSING)
wssFiltResultsStatus :: CritField Text
wssFiltResultsStatus = CF "resultsStatus"

-- | Get the number of scans in your account
getWasScanCount :: (MonadIO m, MonadThrow m) => QualysT m (Maybe Int)
getWasScanCount = do
    res <- processV3With V3v30 "count/was/wasscan" Nothing (return ())
    return $ v3rCount $ fst res

-- | Search WAS scans
runWasSearchScans :: (MonadIO m, MonadThrow m) => Maybe V3Options ->
                     QualysT m (Maybe [WasScan])
runWasSearchScans opt = do
    res <- processV3PageWith V3v30 "search/was/wasscan" opt parseWasScans
    return $ snd res

-- | Retrieve scan details, given the scan ID.
getWasScanDetail :: (MonadIO m, MonadThrow m) => Int ->
                    QualysT m (Maybe WasScan)
getWasScanDetail x = do
    res <- processV3With V3v30 ("get/was/wasscan/" <> show x) Nothing parseWasScan
    return . join $ snd res

-- | Given a scan ID return the status of the scan.
getWasScanStatus :: (MonadIO m, MonadThrow m) => Int -> QualysT m (Maybe Text)
getWasScanStatus x = do
    res <- processV3With V3v30 ("status/was/wasscan/" <> show x) Nothing parseWasScan
    return $ wsStatus =<< (join . snd) res

-- | Given a scan ID, retrieve the results of a scan.
getWasScanResult :: (MonadIO m, MonadThrow m) => Int ->
                    QualysT m (Maybe WasScan)
getWasScanResult x = do
    res <- fetchV3 V3v30 ("download/was/wasscan/" <> show x) Nothing
    parseLBS def (responseBody res) $$ parseWasScan
