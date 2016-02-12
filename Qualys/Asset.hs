{-# LANGUAGE OverloadedStrings, RankNTypes #-}
{-# OPTIONS_GHC -Wwarn #-}
-- | For practical examples see "Qualys.Cookbook.Asset".
module Qualys.Asset
    (
    -- * Actions
      runSearchTags
    -- * Filters
    -- ** Asset/Tag Search Filters
    , amtFiltId
    , amtFiltName
    , amtFiltParentTagId
    , amtFiltRuleType
    , amtFiltColor
    -- * Types
    , SimpleTag (..)
    , Tag (..)
    ) where

import           Control.Applicative hiding (many)
import           Control.Monad (join)
import           Control.Monad.Catch (MonadThrow)
import           Control.Monad.IO.Class (MonadIO)
import           Data.Conduit (ConduitM)
import           Data.Text (Text)
import           Data.Time (UTCTime)
import           Data.XML.Types
import           Text.XML.Stream.Parse

import           Qualys.Internal
import           Qualys.V3api

-- | Filter by ID
amtFiltId :: CritField Int
amtFiltId = CF "id"

-- | Filter by name
amtFiltName :: CritField Text
amtFiltName = CF "name"

-- | Filter by Tag ID
amtFiltParentTagId :: CritField Int
amtFiltParentTagId = CF "parentTagId"

-- | Filter by rule type (STATIC, GROOVY, OS_REGEX, NETWORK_RANGE,
-- NAME_CONTAINS, INSTALLED_SOFTWARE, OPEN_PORTS, VULN_EXIST, ASSET_SEARCH)
amtFiltRuleType :: CritField Text
amtFiltRuleType = CF "ruleType"

-- | Filter by color (#FFFFFF hex format)
amtFiltColor :: CritField Text
amtFiltColor = CF "color"

data SimpleTag = SimpleTag
    { stId   :: Int
    , stName :: Maybe Text
    } deriving (Show, Eq)

data Tag = Tag
    { tId       :: Int
    , tName     :: Maybe Text
    , tParentId :: Maybe Int
    , tCreated  :: Maybe UTCTime
    , tModified :: Maybe UTCTime
    , tColor    :: Maybe Text
    , tRuleText :: Maybe Text
    , tRuleType :: Maybe Text
    , tAssetGrpId :: Maybe Int
    , tBusUnitId  :: Maybe Int
    , tChildren :: Maybe [SimpleTag]
    } deriving (Show,Eq)

parseTags :: (MonadIO m, MonadThrow m) => ConduitM Event o m [Tag]
parseTags = many parseTag

parseTag :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe Tag)
parseTag = tagNoAttr "Tag" $ Tag
    <$> requireWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "name" content
    <*> optionalWith parseUInt (tagNoAttr "parentTagId" content)
    <*> optionalWith parseDate (tagNoAttr "created" content)
    <*> optionalWith parseDate (tagNoAttr "modified" content)
    <*> tagNoAttr "color" content
    <*> tagNoAttr "ruleText" content
    <*> tagNoAttr "ruleType" content
    <*> optionalWith parseUInt (tagNoAttr "srcAssetGroupId" content)
    <*> optionalWith parseUInt (tagNoAttr "srcBusinessUnitId" content)
    <*> (join <$> tagNoAttr "children" (tagNoAttr "list" parseChildren))

parseChildren :: (MonadIO m, MonadThrow m) => ConduitM Event o m [SimpleTag]
parseChildren = many parseChild

parseChild :: (MonadIO m, MonadThrow m) => ConduitM Event o m (Maybe SimpleTag)
parseChild = tagNoAttr "TagSimple" $ SimpleTag
    <$> requireWith parseUInt (tagNoAttr "id" content)
    <*> tagNoAttr "name" content

runSearchTags :: (MonadIO m, MonadThrow m) => Maybe V3Options ->
                 QualysT m (Maybe [Tag])
runSearchTags opt = do
    res <- processV3PageWith V3v20 "search/am/tag" opt parseTags
    return $ snd res

