-- | Internal functions intended only to be used by this package. API stability
--   not guaranteed!
module Qualys.Internal where

import qualified Data.ByteString as B
import Qualys.Core

qualTimeout :: QualysSess -> Int
qualTimeout = qcTimeOut . qConf

qualUser :: QualysSess -> B.ByteString
qualUser = qcUsername . qConf

qualPass :: QualysSess -> B.ByteString
qualPass = qcPassword . qConf

qualPlatform:: QualysSess -> String
qualPlatform = unQualysPlatform . qcPlatform . qConf
