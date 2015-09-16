{-# LANGUAGE OverloadedStrings, RankNTypes #-}
module Qualys.Internal.ParseWebApp
    ( parseWebApps
    , parseWebApp
    ) where

import           Control.Applicative hiding (many)
import           Control.Monad (join)
import           Control.Monad.IO.Class (MonadIO)
import           Control.Monad.Trans.Resource (MonadThrow)
import qualified Data.ByteString.Base64.URL as B64
import           Data.Conduit (ConduitM)
import           Data.Text (Text)
import qualified Data.Text.Encoding as TE
import           Data.XML.Types
import           Text.XML.Stream.Parse

import           Qualys.Internal
import           Qualys.Internal.ParseWasCommon
import           Qualys.Types.Was

parseWebApps :: (MonadIO m, MonadThrow m) => ConduitM Event o m [WebApp]
parseWebApps = many parseWebApp

parseWebApp :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe WebApp)
parseWebApp = tagName "WebApp" ignoreAttrs $ \_ -> WebApp
    <$> requireWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "name" content
    <*> tagNoAttr "url" content
    <*> tagNoAttr "os" content
    <*> tagNoAttr "owner" parseUser
    <*> tagNoAttr "scope" content
    <*> tagNoAttr "subDomain" content
    <*> parseV3List "domains" parseDomain
    <*> parseV3List "uris" parseUri
    <*> parseV3List "attributes" parseAttr
    <*> tagNoAttr "defaultProfile" parseProfile
    <*> tagNoAttr "defaultScanner" parseScanAppl
    <*> optionalWith parseBool (tagNoAttr "scannerLocked" content)
    <*> optionalWith parseBool (tagNoAttr "progressiveScanning" content)
    <*> parseV3List "urlBlacklist" parseUrlEntry
    <*> parseV3List "urlWhitelist" parseUrlEntry
    <*> parseV3List "postDataBlacklist" parseUrlEntry
    <*> parseV3List "authRecords" (tagNoAttr "WebAppAuthRecord" parseAuthRec)
    <*> tagNoAttr "useRobots" content
    <*> optionalWith parseBool (tagNoAttr "useSitemap" content)
    <*> parseV3List "headers" (tagNoAttr "WebAppHeader" content)
    <*> optionalWith parseBool (tagNoAttr "malwareMonitoring" content)
    <*> optionalWith parseBool (tagNoAttr "malwareNotification" content)
    <*> optionalWith parseDate (tagNoAttr "malwareScheduleTime" content)
    <*> tagNoAttr "malwareScheduleTimeZone" content
    <*> parseV3List "tags" parseTag
    <*> parseV3List "comments" (tagNoAttr "Comment" parseComment)
    <*> optionalWith parseBool (tagNoAttr "isScheduled" content)
    <*> parseWasScanInfo
    <*> tagNoAttr "createdBy" parseUser
    <*> optionalWith parseDate (tagNoAttr "createdDate" content)
    <*> tagNoAttr "updatedBy" parseUser
    <*> optionalWith parseDate (tagNoAttr "updatedDate" content)
    <*> optionalWith decodeScrSh (tagNoAttr "screenshot" content)
    <*> tagNoAttr "proxy" parseProxy
    <*> (join <$> tagNoAttr "config" parseConfig)
  where
    -- Decode screenshot leniently, since Qualys doesn't seem to pad base64.
    decodeScrSh = Just . B64.decodeLenient . TE.encodeUtf8
    parseDomain = tagNoAttr "Domain" content
    parseUri    = tagNoAttr "Url" content
    parseAttr :: (MonadThrow m) => ConduitM Event o m (Maybe (Text,Text))
    parseAttr   = tagNoAttr "Attribute" $ (,)
        <$> requireTagNoAttr "category" content
        <*> requireTagNoAttr "value" content
    parseUrlEntry = tagName "UrlEntry" (attr "regex") $ \x -> do
        y <- content
        return $ case x of
            (Just "true") -> UrlRegex y
            _             -> UrlText y
    parseWasScanInfo = tagNoAttr "lastScan" $ WasScanInfo
        <$> requireWith parseUInt (tagNoAttr "id" content)
        <*> tagNoAttr "name" content

parseComment :: (MonadThrow m, MonadIO m) => ConduitM Event o m Comment
parseComment = Comment
    <$> requireTagNoAttr "contents" content
    <*> tagNoAttr "author" parseUser
    <*> optionalWith parseDate (tagNoAttr "createdDate" content)

parseConfig :: (MonadThrow m, MonadIO m) => ConduitM Event o m (Maybe WaConfig)
parseConfig = do
    a <- afterN
    b <- cancelAt
    return $ a <|> b
  where
    afterN = fmap CancelAfterN
        <$> optionalWith parseUInt (tagNoAttr "cancelScansAfterNHours" content)
    cancelAt = fmap CancelScanAt <$> tagNoAttr "cancelScansAt" content
