{-# LANGUAGE OverloadedStrings #-}
-- | For practical examples see "Qualys.Cookbook.VmScan".
module Qualys.Scan
    (
    -- * Actions
      getScanList
    -- * Options
    , sloScanRef
    , sloState
    , sloProcessed
    , sloType
    , sloTarget
    , sloUserLogin
    , sloLaunchedAfter
    , sloLaunchedBefore
    , sloShowAgs
    , sloShowOp
    , sloShowStatus
    , sloShowLast
    -- * Types
    , OptionProfile (..)
    , Scan (..)
    , Status (..)
    ) where

import           Control.Applicative hiding (many)
import           Control.Monad.Catch (MonadThrow (..))
import           Control.Monad.IO.Class (MonadIO)
import           Data.Conduit (($$), ConduitM)
import           Data.Monoid ((<>))
import           Data.Text (Text)
import           Data.Time (UTCTime)
import           Data.XML.Types
import           Network.HTTP.Client
import           Text.XML.Stream.Parse

import           Qualys.Internal
import           Qualys.V2api

-- | Get the entry with this scan reference (e.g. \"scan/987659876.19876\")
sloScanRef :: OptValText a => a -> Param
sloScanRef x = ("scan_ref", toOptTxt x)

-- | Get entries with these states. Valid values are \"Running\",
--   \"Paused\", \"Canceled\", \"Finished\", \"Error\", \"Queued\",
--   or \"Loading\".
sloState :: OptValText a => [a] -> Param
sloState xs = ("state", toOptList toOptTxt xs)

-- | Show scans that have been processed (True) or not processed (False).
sloProcessed :: Bool -> Param
sloProcessed x = ("processed", toOptBool x)

-- | Show only scans of a certain type. Valid values are \"On-Demand\",
--   \"Scheduled\", or \"API\".
sloType :: OptValText a => a -> Param
sloType x = ("type", toOptTxt x)

-- XXX: Ip type
-- | Return scans with the target IP address(es).
sloTarget :: OptValText a => a -> Param
sloTarget x = ("target", toOptTxt x)

-- | Show only scans launched by a user.
sloUserLogin :: OptValText a => a -> Param
sloUserLogin x = ("user_login", toOptTxt x)

-- | Return only scans launched after a certain date/time.
sloLaunchedAfter :: OptValTime a => a -> Param
sloLaunchedAfter x = ("launched_after_datetime", toOptTm x)

-- | Return only scans launched before a certain date/time.
sloLaunchedBefore :: OptValTime a => a -> Param
sloLaunchedBefore x = ("launched_before_datetime", toOptTm x)

-- | True to retrieve asset group information.
sloShowAgs :: Bool -> Param
sloShowAgs x = ("show_ags", toOptBool x)

-- | True to retrieve option profile information
sloShowOp :: Bool -> Param
sloShowOp x = ("show_op", toOptBool x)

-- | True to retrieve the scan status.
sloShowStatus :: Bool -> Param
sloShowStatus x = ("show_status", toOptBool x)

-- | True to see ONLY the most recent scan matching the criteria.
sloShowLast :: Bool -> Param
sloShowLast x = ("show_last", toOptBool x)

data Scan = Scan
    { scId :: Maybe Int
    , scRef :: Text
    , scType :: Text
    , scTitle :: Text
    , scUserLogin :: Text
    , scLaunchDateTime :: UTCTime
    , scDuration       :: Text -- XXX: "Pending" (turn into a maybe?)
    , scProcessed      :: Bool
    , scStatus         :: Maybe Status
    , scTarget         :: Text
    , scAssetGroup     :: Maybe [Text]
    , scOptProfile     :: Maybe OptionProfile
    } deriving Show

data Status = Status
    { scState :: Text
    , scSubState :: Maybe Text
    } deriving Show

data OptionProfile = OptionProfile
    { opTitle   :: Text
    , opDefFlag :: Maybe Bool
    } deriving Show

parseDoc :: MonadThrow m => ConduitM Event o m (Maybe [Scan])
parseDoc = requireTagNoAttr "SCAN_LIST_OUTPUT" parseResp

parseResp :: MonadThrow m => ConduitM Event o m (Maybe [Scan])
parseResp = requireTagNoAttr "RESPONSE" $ do
    parseDiscard "DATETIME"
    parseScans

parseScans :: MonadThrow m => ConduitM Event o m (Maybe [Scan])
parseScans = tagNoAttr "SCAN_LIST" $ many parseScan

parseScan :: MonadThrow m => ConduitM Event o m (Maybe Scan)
parseScan = tagNoAttr "SCAN" $ Scan
    <$> optionalWith parseUInt (tagNoAttr "ID" content)
    <*> requireTagNoAttr "REF" content
    <*> requireTagNoAttr "TYPE" content
    <*> requireTagNoAttr "TITLE" content
    <*> requireTagNoAttr "USER_LOGIN" content
    <*> requireWith parseDate (tagNoAttr "LAUNCH_DATETIME" content)
    <*> requireTagNoAttr "DURATION" content
    <*> requireWith parseBool (tagNoAttr "PROCESSED" content)
    <*> parseStatus
    <*> requireTagNoAttr "TARGET" content
    <*> tagNoAttr "ASSET_GROUP_TITLE_LIST" (many parseAsset)
    <*> parseOptProf
  where
    parseAsset = tagNoAttr "ASSET_GROUP_TITLE" content
    parseOptProf = tagNoAttr "OPTION_PROFILE" $ OptionProfile
        <$> requireTagNoAttr "TITLE" content
        <*> optionalWith parseBool (tagNoAttr "DEFAULT_FLAG" content)

parseStatus :: MonadThrow m => ConduitM Event o m (Maybe Status)
parseStatus = tagNoAttr "STATUS" $ Status
    <$> requireTagNoAttr "STATE" content
    <*> tagNoAttr "SUB_STATE" content

getScanList :: (MonadIO m, MonadThrow m) => [Param] -> QualysT m (Maybe [Scan])
getScanList ps = do
    res <- fetchV2 "scan" ps'
    parseLBS def (responseBody res) $$ parseDoc
  where
    ps' = [("action","list")] <> ps
