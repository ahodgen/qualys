{-# LANGUAGE OverloadedStrings, FlexibleInstances #-}
module Qualys.V2api
    (
      -- * Options Handling
      Param
    , OptValText (..)
    , OptValTime (..)
    , toOptInt
    , toOptBool
    , toOptList
    , uniqueParams
      -- * Types
    , QualRet (..)
      -- * Convenience functions for XML processing
    , parseBool
    , parseUInt
    , parseBound
    , parseSev
    , parseDate
    , requireTagNoAttr
    , requireWith
    , optionalWith
    , parseDiscard
    , parseWarning
      -- * Low-level functions
      -- |
      -- This section contains functions for fetching results from the
      -- Qualys V2 API. You shouldn't need to use these unless you are extending
      -- the API or need low-level access.
    , buildV2ApiUrl
    , fetchV2
    , fetchV2Get
    ) where

import           Control.Applicative
import           Control.Concurrent (threadDelay)
import           Control.Exception (handle, throwIO)
import           Control.Monad.State
import           Control.Monad.Trans.Resource (MonadThrow (..))
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy as BL
import           Data.Conduit (ConduitM)
import qualified Data.Map as M
import           Data.Monoid
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Text.Encoding (encodeUtf8)
import qualified Data.Text.Read as T
import           Data.Time.Calendar (Day)
import           Data.Time.Clock (UTCTime)
import           Data.Time.Format (formatTime, parseTime)
import           Data.XML.Types
import           Network.HTTP.Client
import           Network.HTTP.Types.Header (ResponseHeaders)
import           Network.HTTP.Types.Status (Status(..))
import           System.Locale (defaultTimeLocale)
import           Text.XML.Stream.Parse

import          Qualys.Internal

type Param = (B.ByteString, B.ByteString)

-- | A class for converting texty type option values into a ByteString.
class OptValText a where
    toOptTxt :: a -> B.ByteString

instance OptValText Text where
    toOptTxt = encodeUtf8

instance OptValText [Char] where
    toOptTxt = B8.pack

instance OptValText B.ByteString where
    toOptTxt = id

-- | A class for converting time based option values into a ByteString.
class OptValTime a where
    toOptTm :: a -> B.ByteString

instance OptValTime UTCTime where
    toOptTm = B8.pack . formatTime defaultTimeLocale "%FT%TZ"

instance OptValTime Day where
    toOptTm = B8.pack . formatTime defaultTimeLocale "%F"

-- | Integral option value to a ByteString
toOptInt :: (Integral a, Show a) => a -> B.ByteString
toOptInt = B8.pack . show

-- | Boolean option value into a ByteString
toOptBool :: Bool -> B.ByteString
toOptBool True  = "1"
toOptBool False = "0"

-- | List of option values to a ByteString
toOptList :: (a -> B.ByteString) -> [a] -> B.ByteString
toOptList f xs = B.intercalate "," $ fmap f xs

-- | Make a list of parameters unique. Values to the right are selected
--   if a duplicate is encountered.
uniqueParams :: [Param] -> [Param]
uniqueParams = M.toList . M.fromList

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

-- | Parse a text value into UTCTime
parseDate :: Text -> Maybe UTCTime
parseDate = parseTime defaultTimeLocale "%FT%T%QZ" . T.unpack

requireTagNoAttr :: (MonadThrow m) => Name -> ConduitM Event o m a ->
                    ConduitM Event o m a
requireTagNoAttr x = force err . tagNoAttr x
  where
    err = "Tag '" <> show x <> "' required!"

-- | Force a value with a parsing function.
requireWith :: (Text -> Maybe a) -> ConduitM Event o m (Maybe Text) ->
             ConduitM Event o m a
requireWith p i = do
    x <- i
    case join $ fmap p x of
        Nothing -> fail $ "Bad value '" <> show x <> "'"
        Just y  -> return y

optionalWith :: MonadThrow m => (a -> Maybe b) ->
                ConduitM Event o m (Maybe a) -> ConduitM Event o m (Maybe b)
optionalWith f v = do
    x <- v
    return $ f =<< x

-- | Convenience function for ignoring an element and content
parseDiscard :: (MonadThrow m) => Name -> ConduitM Event o m ()
parseDiscard x = void $ tagNoAttr x contentMaybe

-- | Return value (<WARNING>) from Qualys
data QualRet = QualRet
    { qrCode :: Maybe Text
    , qrMsg  :: Maybe Text
    , qrUrl  :: Maybe Text
    } deriving Show

-- | Parse warnings/errors from Qualys.
parseWarning :: (MonadThrow m) => ConduitM Event o m (Maybe QualRet)
parseWarning = tagNoAttr "WARNING" $ QualRet
    <$> tagNoAttr "CODE" content
    <*> tagNoAttr "TEXT" content
    <*> tagNoAttr "URL"  content

v2ApiPath :: String
v2ApiPath = "/api/2.0/fo/"

buildV2ApiUrl :: MonadIO m => String -> QualysT m String
buildV2ApiUrl x = do
    sess <- liftState get
    return $ "https://" <> qualPlatform sess <> v2ApiPath <> x

rateLimitDelay :: ResponseHeaders -> IO Int
rateLimitDelay xs =
    case rlExceed <|> (clExcDelay =<< clExceed) of
        Nothing -> do
            putStrLn "Qualys blocked (409 Conflict) for an unknown reason."
            putStrLn "Headers follow. Retrying in 60 seconds."
            print xs
            return 60
        Just z -> return z
  where
    toWait  = lookup "X-RateLimit-ToWait-Sec" xs
    limit   = lookup "X-Concurrency-Limit-Limit" xs
    running = lookup "X-Concurrency-Limit-Running" xs
    rlExceed = rlInt =<< toWait
    clExceed = (>=) <$> running <*> limit
    clExcDelay True  = Just 60
    clExcDelay False = Nothing
    rlInt x = case B8.readInt x of
        Just (y,"") -> Just y
        _           -> Nothing

rateLimit :: Request -> QualysSess -> IO (Response BL.ByteString)
rateLimit req sess = handle rlErr $ httpLbs req (qManager sess)
  where
    rlErr (StatusCodeException (Status 409 _) hs _) = do
        rld <- rateLimitDelay hs
        print $ "DELAY " <> show rld <> " seconds."
        threadDelay (rld*1000000)
        rateLimit req sess
    rlErr x = throwIO x

-- | Fetch a Qualys V2 API response via POST given a path (e.g. "session/")
--   and a list of parameters.
fetchV2 :: MonadIO m => String -> [Param] -> QualysT m (Response BL.ByteString)
fetchV2 p params = do
    sess <- liftState get
    url <- buildV2ApiUrl p
    req <- liftIO $ parseUrl url
    let req' = req { method = "POST"
                   , requestHeaders = qualysHeaders
                   , cookieJar = Just $ qCookieJar sess
                   , responseTimeout = Just (1000000 * qualTimeout sess)
                   }
    let req'' = urlEncodedBody params $
                applyBasicAuth (qualUser sess) (qualPass sess) req'
    liftIO $ rateLimit req'' sess

-- | Get a Qualys V2 API response given a full URL.
fetchV2Get :: MonadIO m => String -> QualysT m (Response BL.ByteString)
fetchV2Get url = do
    sess <- liftState get
    req <- liftIO $ parseUrl url
    let req' = req { method = "GET"
                   , requestHeaders = qualysHeaders
                   , cookieJar = Just $ qCookieJar sess
                   , responseTimeout = Just (1000000 * qualTimeout sess)
                   }
    let req'' = applyBasicAuth (qualUser sess) (qualPass sess) req'
    liftIO $ rateLimit req'' sess

{-
 -- Session based auth for V2 API.
qualSess :: MonadIO m => [(B.ByteString, B.ByteString)] ->
                         QualysT m (Response BL.ByteString)
qualSess params = do
    sess <- get
    url <- buildV2ApiUrl "session/"
    req <- liftIO $ parseUrl url
    let req' = req { method = "POST"
                   , requestHeaders = qualysHeaders
                   , cookieJar = Just $ qCookieJar sess
                   , responseTimeout = Just (1000000 * qualTimeout sess)
                   }
    let req'' = urlEncodedBody params req'
    liftIO $ httpLbs req'' (qManager sess)

qualysV2Auth :: MonadIO m => QualysT m ()
qualysV2Auth = do
    sess <- get
    res <- qualSess (postParam sess)
    put $ sess
        { qCookieJar = responseCookieJar res
        , qV2Auth = return ()
        , qV2Unauth = qualysV2UnAuth
        }
    return ()
  where
    postParam s =
        [ ("action","login")
        , ("username",qualUser s)
        , ("password", qualPass s)
        ]

qualysV2UnAuth :: MonadIO m => QualysT m ()
qualysV2UnAuth = do
    _ <- qualSess param
    return ()
  where
    param = [("action","logout")]
-}
