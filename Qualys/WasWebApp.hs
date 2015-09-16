{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wwarn #-}
-- | For practical examples see "Qualys.Cookbook.WasWebApp".
module Qualys.WasWebApp
    (
    -- * Actions
      searchWebApps
    , getWebAppDetail
    -- * Filters
    -- ** Search Web App Filters
    , wasFiltId
    , wasFiltName
    , wasFiltUrl
    , wasFiltTags
    , wasFiltTagName
    , wasFiltTagId
    , wasFiltCreateDate
    , wasFiltUpdateDate
    , wasFiltIsSched
    , wasFiltIsScanned
    , wasFiltLastScan
    , wasFiltLastScanStatus
    -- * Types
    , WebApp (..)
    , UrlEntry (..)
    , Comment (..)
    , WaConfig (..)
    ) where

import           Control.Monad (join)
import           Data.Monoid ((<>))
import           Data.Text (Text)
import           Data.Time (UTCTime)

import           Qualys.Internal
import           Qualys.Internal.ParseWebApp
import           Qualys.Types.Was
import           Qualys.V3api

-- | Filter by WebApp ID.
wasFiltId :: CritField Int
wasFiltId = CF "id"

-- | Filter by WebApp name.
wasFiltName :: CritField Text
wasFiltName = CF "name"

-- | Filter by the WebApp URL.
wasFiltUrl :: CritField Text
wasFiltUrl = CF "url"

-- | Filter if no tags.
wasFiltTags :: CritField ()
wasFiltTags = CF "tags"

-- | Filter by tag name.
wasFiltTagName :: CritField Text
wasFiltTagName = CF "tags.name"

-- | Filter by tag ID.
wasFiltTagId :: CritField Int
wasFiltTagId = CF "tags.id"

-- | Filter by creation date/time.
wasFiltCreateDate :: CritField UTCTime
wasFiltCreateDate = CF "createdDate"

-- | Filter by update date/time.
wasFiltUpdateDate :: CritField UTCTime
wasFiltUpdateDate = CF "updatedDate"

-- | Filter if the WebApp is scheduled (True) or not (False).
wasFiltIsSched :: CritField Bool
wasFiltIsSched = CF "isScheduled"

-- | Filter if the WebApp has been scanned.
wasFiltIsScanned :: CritField Bool
wasFiltIsScanned = CF "isScanned"

-- | Filter by the WebApp's last scanned date/time.
wasFiltLastScan :: CritField UTCTime
wasFiltLastScan = CF "lastScan.date"

-- | Filter by the WebApp's last scan status (SUBMITTED, RUNNING, FINISHED,
--   ERROR or CANCELLED)
wasFiltLastScanStatus :: CritField Text
wasFiltLastScanStatus = CF "lastScan.status"

-- | Search for WebApps. If no options are given it will return all WebApps
--   in the subscription.
searchWebApps :: Maybe V3Options -> QualysT IO (Maybe [WebApp])
searchWebApps opt = do
    res <- processV3With "search/was/webapp" opt parseWebApps
    return $ snd res

-- | Get details for a WebApp.
getWebAppDetail ::  Int -> QualysT IO (Maybe WebApp)
getWebAppDetail x = do
    res <- processV3With ("get/was/webapp/" <> show x) Nothing parseWebApp
    return . join $ snd res
