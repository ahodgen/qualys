{-# LANGUAGE OverloadedStrings, RankNTypes #-}
module Qualys.Internal.ParseWasScan
    ( parseWasScans
    , parseWasScan
    ) where

import           Control.Applicative hiding (many)
import           Control.Monad.Catch (MonadThrow)
import           Control.Monad.IO.Class (MonadIO)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import           Data.Conduit (ConduitM, Consumer)
import           Data.Text (Text)
import qualified Data.Text.Encoding as TE
import           Data.XML.Types
import           Text.XML.Stream.Parse

import           Qualys.Internal
import           Qualys.Internal.ParseWasCommon
import           Qualys.Internal.ParseWasAuthRec
import           Qualys.Types.Was

parseWasScans :: (MonadIO m, MonadThrow m) => ConduitM Event o m [WasScan]
parseWasScans = many parseWasScan

parseWasScan :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe WasScan)
parseWasScan = tagName "WasScan" ignoreAttrs $ \_ -> WasScan
    <$> requireWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "name" content
    <*> tagNoAttr "reference" content
    <*> tagNoAttr "type" content
    <*> tagNoAttr "mode" content
    <*> optionalWith parseBool (tagNoAttr "multi" content)
    <*> optionalWith parseBool (tagNoAttr "progressiveScanning" content)
    <*> parseTarget
    <*> tagNoAttr "profile" parseProfile
    <*> optionalWith parseUInt (tagNoAttr "cancelAfterNHours" content)
    <*> tagNoAttr "cancelTime" content
    <*> parseOpts
    <*> optionalWith parseDate (tagNoAttr "launchedDate" content)
    <*> tagNoAttr "launchedBy" parseUser
    <*> tagNoAttr "status" content
    <*> optionalWith parseDate (tagNoAttr "endScanDate" content)
    <*> optionalWith parseUInt (tagNoAttr "scanDuration" content)
    <*> parseSummary
    <*> parseStat
    <*> parseVulns
    <*> parseSensConts
    <*> parseScanIgs

parseTarget :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe WsTarget)
parseTarget = tagNoAttr "target" $ WsTarget
    <$> parseWebApps
    <*> parseV3List "tags" parseTag
    <*> requireWith Just parseWebApp
    <*> parseAuthRec
    <*> tagNoAttr "scannerAppliance" parseScanAppl
    <*> tagNoAttr "cancelOption" content
    <*> tagNoAttr "proxy" parseProxy

parseWebApps :: (MonadIO m, MonadThrow m) =>
                ConduitM Event o m (Maybe [WsWebApp])
parseWebApps = parseV3List "webAppList" parseWebApp

parseWebApp :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe WsWebApp)
parseWebApp = tagNoAttr "webApp" $ WsWebApp
    <$> optionalWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "name" content
    <*> tagNoAttr "url" content

parseOpts :: (MonadIO m, MonadThrow m) =>
             ConduitM Event o m (Maybe [(Text,Text)])
parseOpts = parseV3List "options" parseOpt
  where
    parseOpt :: (MonadIO m, MonadThrow m) =>
                ConduitM Event o m (Maybe (Text,Text))
    parseOpt = tagNoAttr "WasScanOption" $ (,)
        <$> requireTagNoAttr "name" content
        <*> requireTagNoAttr "value" content

parseSummary :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe WsSummary)
parseSummary = tagNoAttr "summary" $ WsSummary
    <$> optionalWith parseUInt (tagNoAttr "crawlDuration" content)
    <*> optionalWith parseUInt (tagNoAttr "testDuration" content)
    <*> optionalWith parseUInt (tagNoAttr "linksCrawled" content)
    <*> optionalWith parseUInt (tagNoAttr "nbRequests" content)
    <*> requireTagNoAttr "resultsStatus" content
    <*> requireTagNoAttr "authStatus" content
    <*> tagNoAttr "os" content

parseStat :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe WsStat)
parseStat = tagNoAttr "stats" $ WsStat
    <$> parseGlobalStat
    <*> parseGroupStat
    <*> parseOwaspStat
    <*> parseWascStat

parseGlobalStat :: (MonadIO m, MonadThrow m) =>
                   ConduitM Event o m (Maybe WsGlobalStat)
parseGlobalStat = tagNoAttr "global" $ WsGlobalStat
    <$> requireWith parseUInt (tagNoAttr "nbVulnsTotal" content)
    <*> requireWith parseUInt (tagNoAttr "nbVulnsLevel5" content)
    <*> requireWith parseUInt (tagNoAttr "nbVulnsLevel4" content)
    <*> requireWith parseUInt (tagNoAttr "nbVulnsLevel3" content)
    <*> requireWith parseUInt (tagNoAttr "nbVulnsLevel2" content)
    <*> requireWith parseUInt (tagNoAttr "nbVulnsLevel1" content)
    <*> requireWith parseUInt (tagNoAttr "nbScsTotal" content)
    <*> requireWith parseUInt (tagNoAttr "nbScsLevel5" content)
    <*> requireWith parseUInt (tagNoAttr "nbScsLevel4" content)
    <*> requireWith parseUInt (tagNoAttr "nbScsLevel3" content)
    <*> requireWith parseUInt (tagNoAttr "nbScsLevel2" content)
    <*> requireWith parseUInt (tagNoAttr "nbScsLevel1" content)
    <*> requireWith parseUInt (tagNoAttr "nbIgsTotal" content)
    <*> requireWith parseUInt (tagNoAttr "nbIgsLevel5" content)
    <*> requireWith parseUInt (tagNoAttr "nbIgsLevel4" content)
    <*> requireWith parseUInt (tagNoAttr "nbIgsLevel3" content)
    <*> requireWith parseUInt (tagNoAttr "nbIgsLevel2" content)
    <*> requireWith parseUInt (tagNoAttr "nbIgsLevel1" content)

parseGroupStat :: (MonadIO m, MonadThrow m) =>
                  ConduitM Event o m (Maybe [WsNameStat])
parseGroupStat = parseV3List "byGroup" parseGrp
  where
    parseGrp :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe WsNameStat)
    parseGrp = tagNoAttr "GroupStat" (parseNameStat "group")

parseOwaspStat :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe [WsNameStat])
parseOwaspStat = parseV3List "byOwasp" parseOwasp
  where
    parseOwasp :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe WsNameStat)
    parseOwasp = tagNoAttr "OwaspStat" (parseNameStat "owasp")

parseWascStat :: (MonadIO m, MonadThrow m) =>
                 ConduitM Event o m (Maybe [WsNameStat])
parseWascStat = parseV3List "byWasc" parseWasc
  where
    parseWasc :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe WsNameStat)
    parseWasc = tagNoAttr "WascStat" (parseNameStat "wasc")

parseNameStat :: (MonadIO m, MonadThrow m) =>
                 Name -> ConduitM Event o m WsNameStat
parseNameStat x = WsNameStat
    <$> requireTagNoAttr x content
    <*> requireWith parseUInt (tagNoAttr "nbTotal" content)
    <*> requireWith parseUInt (tagNoAttr "nbLevel5" content)
    <*> requireWith parseUInt (tagNoAttr "nbLevel4" content)
    <*> requireWith parseUInt (tagNoAttr "nbLevel3" content)
    <*> requireWith parseUInt (tagNoAttr "nbLevel2" content)
    <*> requireWith parseUInt (tagNoAttr "nbLevel1" content)

parseVulns :: (MonadIO m, MonadThrow m)
           => ConduitM Event o m (Maybe [WsScanResult])
parseVulns = parseScanResults "vulns" "WasScanVuln" fi
  where
    fi = parseInsts "instances" "WasScanVulnInstance" fp
    fp = parsePayloads "payloads" "WasScanVulnPayload"

parseSensConts :: (MonadIO m, MonadThrow m)
               => ConduitM Event o m (Maybe [WsScanResult])
parseSensConts = parseScanResults "sensitiveContents"
                                  "WasScanSensitiveContentPayload" fi
  where
    fi = parseInsts "instances"
                    "WasScanSensitiveContentInstance" fp
    fp = parsePayloads "payloads"
                       "WasScanSensitiveContentPayload"

parseScanResults :: (MonadIO m, MonadThrow m)
                 => Name
                 -> Name
                 -> Consumer Event m (Maybe [WsInstance])
                 -> ConduitM Event o m (Maybe [WsScanResult])
parseScanResults lst ele fi = parseV3List lst (parseScanResult ele fi)

parseScanResult :: (MonadIO m, MonadThrow m)
                => Name
                -> ConduitM Event o m (Maybe [WsInstance])
                -> ConduitM Event o m (Maybe WsScanResult)
parseScanResult x fi = tagNoAttr x $ WsScanResult
        <$> (QID <$> requireWith parseUInt (tagNoAttr "qid" content))
        <*> requireTagNoAttr "title" content
        <*> requireTagNoAttr "uri" content
        <*> tagNoAttr "param" content
        <*> tagNoAttr "content" content -- XXX:
        <*> fi

parseInsts :: (MonadIO m, MonadThrow m) =>
    Name ->
    Name ->
    Consumer Event m (Maybe [WsPayload]) ->
    ConduitM Event o m (Maybe [WsInstance])
parseInsts lst ele fp = parseV3List lst (parseInst ele fp)

parseInst :: (MonadIO m, MonadThrow m) =>
             Name ->
             ConduitM Event o m (Maybe [WsPayload]) ->
             ConduitM Event o m (Maybe WsInstance)
parseInst x fp = tagNoAttr x $ WsInstance
        <$> requireWith parseBool (tagNoAttr "authenticated" content)
        <*> tagNoAttr "form" content
        <*> fp

parsePayloads :: (MonadIO m, MonadThrow m) => Name -> Name ->
                 ConduitM Event o m (Maybe [WsPayload])
parsePayloads lst ele = parseV3List lst (parsePayload ele)

parsePayload :: (MonadIO m, MonadThrow m) =>
                Name -> ConduitM Event o m (Maybe WsPayload)
parsePayload x = tagNoAttr x $ WsPayload
    <$> requireTagNoAttr "payload" content
    <*> requireBase64 "result"

parseScanIgs :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe [WsIg])
parseScanIgs = parseV3List "igs" parseIg
  where
    parseIg :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe WsIg)
    parseIg = tagNoAttr "WasScanIg" $ WsIg
        <$> (QID <$> requireWith parseUInt (tagNoAttr "qid" content))
        <*> requireTagNoAttr "title" content
        <*> requireBase64 "data"

requireBase64 :: MonadThrow m => Name -> ConduitM Event o m B.ByteString
requireBase64 x = requireWith dc (tagName x (attr "base64") ra)
  where
    dc :: (Maybe Text, Text) -> Maybe B.ByteString
    dc (b64,t) = case b64 of
            -- Using decodeLenient, since Qualys doesn't use proper padding.
            Just "true" -> Just $ B64.decodeLenient $ TE.encodeUtf8 t
            _           -> Just $ TE.encodeUtf8 t
    ra t = do
        y <- content
        return (t, y)
