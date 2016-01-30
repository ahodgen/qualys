{-# LANGUAGE OverloadedStrings, FlexibleInstances #-}
-- | For practical examples see "Qualys.Cookbook.Report".
module Qualys.Report
    (
    -- * Actions
      fetchReport
    , launchReport
    , statusReport
    , launchFetchReport
    -- * Options
    , lroTemplateId
    , lroReportTitle
    , lroOutFormat
    , lroHideHeader
    , lroIps
    -- * Types
    , ReportId
    ) where

import           Control.Concurrent (threadDelay)
import           Control.Monad.Catch (MonadThrow (..))
import           Control.Monad.IO.Class (liftIO, MonadIO)
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Char8 as B8
import           Data.Monoid
import           Data.Text (Text, unpack)
import           Network.HTTP.Client
import           Text.XML
import           Text.XML.Cursor

import           Qualys.Internal
import           Qualys.Log
import           Qualys.V2api

-- * Options for the Qualys Report API

-- | The template ID of the report you want to launch.
lroTemplateId :: (Integral a, Show a) => a -> Param
lroTemplateId x = ("template_id", toOptInt x)

-- | User-defined Report Title (max 128 characters).
lroReportTitle :: OptValText a => a -> Param
lroReportTitle x = ("report_title", toOptTxt x)

-- | Output format for the report (pdf, csv, etc.)
lroOutFormat :: OptValText a => a -> Param
lroOutFormat x = ("output_format", toOptTxt x)

-- | Hide (True) or include (False) a header for CSV reports.
lroHideHeader :: Bool -> Param
lroHideHeader x = ("hide_header", toOptBool x)

lroIps :: OptValText a => a -> Param
lroIps x = ("ips", toOptTxt x)

newtype ReportId = ReportId Text

-- | Fetch a report
fetchReport :: (MonadIO m, MonadThrow m) => ReportId -> QualysT m B.ByteString
fetchReport (ReportId r) = do
    res <- fetchV2 "report" param
    return $ responseBody res
  where
    param = [ ("action", "fetch")
            , ("id",     B8.pack $ unpack r)
            ]

-- | Launch a report.
launchReport :: (MonadIO m, MonadThrow m) => [Param] -> QualysT m ReportId
launchReport param = do
    res <- fetchV2 "report" ([("action","launch")] <> param)
    return . ReportId . head $ xmlId res
  where
    xml r = fromDocument . parseLBS_ def $ responseBody r
    xmlId r = content =<< child =<< element "VALUE" =<< child =<<
              element "ITEM" =<< child =<< element "ITEM_LIST" =<< child =<<
              element "RESPONSE" =<< child (xml r)

-- | List a report
statusReport :: (MonadIO m, MonadThrow m) => ReportId -> QualysT m [Text]
statusReport (ReportId r) = do
    res <- fetchV2 "report" param
    return $ xStat res
  where
    param = [ ("action", "list")
            , ("id",     B8.pack $ unpack r)
            ]
    xml x   = fromDocument . parseLBS_ def $ responseBody x
    xStat x = content =<< child =<< element "STATE" =<< child =<<
              element "STATUS" =<< child =<< element "REPORT" =<< child =<<
              element "REPORT_LIST" =<< child =<<
              element "RESPONSE" =<< child (xml x)

-- | Launch and fetch a report
launchFetchReport :: (MonadIO m, MonadThrow m) => [Param] -> QualysT m B.ByteString
launchFetchReport ps = do
    rid <- launchReport ps
    reDo rid
    fetchReport rid
  where
    act r x = case x of
        [] -> do
            qLog QLogWarn "statusReport: empty stat!"
            reDo r
        ["Finished"] -> return ()
        [e]          -> do
            qLog QLogWarn $ "statusReport: " <> e
            reDo r
        _            -> do
            qLog QLogWarn "statusReport: Multiple stats!"
            reDo r
    reDo r = do
        liftIO $ threadDelay (60*1000000)
        rs <- statusReport r
        act r rs
