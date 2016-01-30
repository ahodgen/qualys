{-# LANGUAGE OverloadedStrings #-}
module Qualys.Internal.ParseWasAuthRec
    ( parseAuthRecs
    , parseAuthRec
    ) where

import           Control.Applicative hiding (many)
import           Control.Monad.Catch (MonadThrow)
import           Control.Monad.IO.Class (MonadIO)
import           Data.Conduit (ConduitM)
import           Data.XML.Types
import           Text.XML.Stream.Parse

import           Qualys.Internal
import           Qualys.Internal.ParseWasCommon
import           Qualys.Types.Was

parseAuthRecs :: (MonadIO m, MonadThrow m) => ConduitM Event o m [WsAuthRec]
parseAuthRecs = many parseAuthRec

parseAuthRec :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe WsAuthRec)
parseAuthRec = tagName "WebAppAuthRecord" ignoreAttrs $ \_ -> WsAuthRec
    <$> requireWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "name" content
    <*> tagNoAttr "owner" parseUser
    <*> tagNoAttr "formRecord" parseFormRecord
    <*> tagNoAttr "serverRecord" parseServRecord
    <*> parseV3List "tags" parseTag
    <*> parseV3List "comments" (tagNoAttr "Comment" parseComment)
    <*> optionalWith parseDate (tagNoAttr "createdDate" content)
    <*> tagNoAttr "createdBy" parseUser
    <*> optionalWith parseDate (tagNoAttr "updatedDate" content)
    <*> tagNoAttr "updatedBy" parseUser

parseFormRecord :: (MonadIO m, MonadThrow m) => ConduitM Event o m WaFormRecord
parseFormRecord = WaFormRecord
    <$> tagNoAttr "type" content
    <*> optionalWith parseBool (tagNoAttr "sslOnly" content)
    <*> tagNoAttr "seleniumScript" parseSelScript
    <*> parseV3List "fields" (tagNoAttr "WebAppAuthFormRecordField" parseFrFld)

parseSelScript :: (MonadIO m, MonadThrow m) => ConduitM Event o m SelScript
parseSelScript = SelScript
    <$> tagNoAttr "name" content
    <*> tagNoAttr "data" content
    <*> tagNoAttr "regex" content

parseFrFld :: (MonadIO m, MonadThrow m) => ConduitM Event o m WfrField
parseFrFld = WfrField
    <$> requireWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "name" content
    <*> optionalWith parseBool (tagNoAttr "secured" content)
    <*> tagNoAttr "value" content

parseServRecord :: (MonadIO m, MonadThrow m) => ConduitM Event o m ServRecord
parseServRecord = ServRecord
    <$> optionalWith parseBool (tagNoAttr "sslOnly" content)
    <*> tagNoAttr "certificate" parseCert
    <*> parseV3List "fields" (tagNoAttr "WebAppAuthServerRecordField" parseSrFld)

parseSrFld :: (MonadIO m, MonadThrow m) => ConduitM Event o m SrField
parseSrFld = SrField
    <$> requireWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "type" content
    <*> tagNoAttr "domain" content
    <*> tagNoAttr "username" content
    <*> tagNoAttr "password" content

parseCert :: (MonadIO m, MonadThrow m) => ConduitM Event o m Certificate
parseCert = Certificate
    <$> tagNoAttr "name" content
    <*> tagNoAttr "contents" content
    <*> tagNoAttr "passphrase" content
