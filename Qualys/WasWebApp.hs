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
import           Data.Proxy
import           Data.Text (Text)
import           Data.Time (UTCTime)

import           Qualys.Internal
import           Qualys.Internal.ParseWebApp
import           Qualys.Types.Was
import           Qualys.V3api

-- | Filter by WebApp ID.
wasFiltId :: (Text, Proxy Int)
wasFiltId = ("id", Proxy)

-- | Filter by WebApp name.
wasFiltName :: (Text, Proxy Text)
wasFiltName = ("name", Proxy)

-- | Filter by the WebApp URL.
wasFiltUrl :: (Text, Proxy Text)
wasFiltUrl = ("url", Proxy)

-- | Filter if no tags.
wasFiltTags :: (Text, Proxy ())
wasFiltTags = ("tags", Proxy)

-- | Filter by tag name.
wasFiltTagName :: (Text, Proxy Text)
wasFiltTagName = ("tags.name", Proxy)

-- | Filter by tag ID.
wasFiltTagId :: (Text, Proxy Int)
wasFiltTagId = ("tags.id", Proxy)

-- | Filter by creation date/time.
wasFiltCreateDate :: (Text, Proxy UTCTime)
wasFiltCreateDate = ("createdDate", Proxy)

-- | Filter by update date/time.
wasFiltUpdateDate :: (Text, Proxy UTCTime)
wasFiltUpdateDate = ("updatedDate", Proxy)

-- | Filter if the WebApp is scheduled (True) or not (False).
wasFiltIsSched :: (Text, Proxy Bool)
wasFiltIsSched = ("isScheduled", Proxy)

-- | Filter if the WebApp has been scanned.
wasFiltIsScanned :: (Text, Proxy Bool)
wasFiltIsScanned = ("isScanned", Proxy)

-- | Filter by the WebApp's last scanned date/time.
wasFiltLastScan :: (Text, Proxy UTCTime)
wasFiltLastScan = ("lastScan.date", Proxy)

-- | Filter by the WebApp's last scan status (SUBMITTED, RUNNING, FINISHED,
--   ERROR or CANCELLED)
wasFiltLastScanStatus :: (Text, Proxy Text)
wasFiltLastScanStatus = ("lastScan.status", Proxy)

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
