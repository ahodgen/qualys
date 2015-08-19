{-# LANGUAGE OverloadedStrings #-}
module Qualys.Options where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Data.Time.Clock (UTCTime)
import Data.Time.Format (formatTime)
import System.Locale (defaultTimeLocale)

class QualysOption a where
    toQualysParam :: a -> [(B.ByteString, B.ByteString)]

instance QualysOption a => QualysOption (Maybe a) where
    toQualysParam Nothing  = []
    toQualysParam (Just x) = toQualysParam x

instance QualysOption a => QualysOption [a] where
    toQualysParam xs = concat $ fmap toQualysParam xs

qualysTimeOpt :: UTCTime -> B.ByteString
qualysTimeOpt = B8.pack . formatTime defaultTimeLocale "%FT%TZ"

showToBs :: Show a => a -> B.ByteString
showToBs = B8.pack . show

