{-# LANGUAGE OverloadedStrings, RankNTypes #-}
module Qualys.Internal.ParseWasCommon
    ( parseProfile
    , parseTag
    , parseAuthRec
    , parseProxy
    , parseUser
    , parseScanAppl
    , parseV3List
    ) where

import           Control.Applicative hiding (many)
import           Control.Monad (join)
import           Control.Monad.IO.Class (MonadIO)
import           Control.Monad.Trans.Resource (MonadThrow)
import           Data.Conduit (ConduitM, Consumer)
import           Data.XML.Types
import           Text.XML.Stream.Parse

import           Qualys.Internal
import           Qualys.Types.Was

parseProfile :: (MonadIO m, MonadThrow m) => ConduitM Event o m WsScanProfile
parseProfile = WsScanProfile
    <$> optionalWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "name" content

parseTag :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe WsTag)
parseTag = tagNoAttr "Tag" $ WsTag
    <$> requireWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "name" content

parseAuthRec :: (MonadIO m, MonadThrow m) => ConduitM Event o m WsAuthRec
parseAuthRec = WsAuthRec
    <$> optionalWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "name" content

parseProxy :: (MonadIO m, MonadThrow m) => ConduitM Event o m WsProxy
parseProxy = WsProxy
    <$> optionalWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "name" content
    <*> tagNoAttr "url" content

parseUser :: (MonadIO m, MonadThrow m) => ConduitM Event o m WsUser
parseUser = WsUser
    <$> optionalWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "username" content
    <*> tagNoAttr "firstName" content
    <*> tagNoAttr "lastName" content

parseScanAppl :: (MonadIO m, MonadThrow m) => ConduitM Event o m ScanAppl
parseScanAppl = ScanAppl
    <$> requireTagNoAttr "type" content
    <*> tagNoAttr "friendlyName" content

parseV3List :: (MonadIO m, MonadThrow m)
            => Name -- ^ Name of the list
            -> Consumer Event m (Maybe a) -- ^ function to parse list items
            -> ConduitM Event o m (Maybe [a])
parseV3List x f = do
    xs <- tagNoAttr x $ do
        parseDiscard "count"
        tagNoAttr "list" (many f)
    return $ join xs
