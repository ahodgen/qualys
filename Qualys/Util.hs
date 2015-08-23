{-# LANGUAGE OverloadedStrings #-}
module Qualys.Util where

import           Data.Text (Text)
import qualified Data.Text.Read as T

-- | Parse a text into a Bool, using the Qualys notion of true and false.
parseBool :: Text -> Maybe Bool
parseBool "0" = Just False
parseBool "1" = Just True
parseBool _   = Nothing

parseUInt :: Integral a => Text -> Maybe a
parseUInt x = case T.decimal x of
    Right (n,"") -> Just n
    _            -> Nothing

parseBound :: Integral a => a -> a -> Text -> Maybe a
parseBound mn mx x = check =<< parseUInt x
  where
    check n
        | n >= mn && n <= mx = Just n
        | otherwise          = Nothing

-- Parse a text value into a severity, enforcing the correct range.
parseSev :: Integral a => Text -> Maybe a
parseSev = parseBound 0 5
