{-# LANGUAGE OverloadedStrings #-}
-- | Logging
module Qualys.Log where

import           Control.Monad (when)
import           Control.Monad.IO.Class (liftIO, MonadIO)
import           Control.Monad.Reader (ask)
import           Data.Monoid ((<>))
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import           Data.Time (getCurrentTime)
import           GHC.IO.Handle
import           GHC.IO.Handle.FD

import           Qualys.Internal

-- | Only log messages when predicate p is true
logFilter :: MonadIO m => Logger m -> (QLogLevel -> Text -> Bool) -> Logger m
logFilter f p l m = when (p l m) $ f l m

-- | Logger to drop logs
logDrop :: MonadIO m => Logger m
logDrop _ _ = return ()

-- | Log messages to a file descriptor
logFd :: MonadIO m => Handle -> Logger m
logFd h l m = do
    now <- liftIO getCurrentTime
    liftIO  $ T.hPutStr h (logline now)
  where
    logline t = (T.pack . show) t <> " " <>
                "[" <> (T.pack . show) l <> "] " <>
                m <> "\n"

-- | Log messages to standard error
logStderr :: MonadIO m => Logger m
logStderr = logFd stderr

-- | Logging in QualysT
qLog :: MonadIO m => QLogLevel -> Text -> QualysT m ()
qLog lvl mess = do
    sess <- liftReader ask
    liftIO $ qualLogger sess lvl mess

-- | Logging outside of QualysT
logRaw  :: MonadIO m => Logger m -> QLogLevel -> Text -> m ()
logRaw lg = lg
