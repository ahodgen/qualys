--  Examples of using "Qualys.Knowledgebase". This is a documentation-only
--   module.
module Qualys.Cookbook.KnowledgeBase (
-- $exampleOption1

-- $exampleOption2

) where

-- $exampleOption1
--
-- Get all details for any entries modified in the last two days, and print
-- them.
--
--  @
--  {-\# LANGUAGE OverloadedStrings \#-}
--  import Control.Monad.IO.Class (liftIO)
--  import Data.Time(getCurrentTime, addUTCTime)
--  import Qualys
--
--  myConf :: QualysConf
--  myConf = QualysConf
--      { qcPlatform = qualysUSPlatform2
--      , qcUsername = \"myuser\"
--      , qcPassword = \"mypass\"
--      , qcTimeOut  = 600 -- 10 Minutes
--      }
--
--  main :: IO ()
--  main = do
--      now <- getCurrentTime
--      let opts = [ kboModAfter (twodaysago now)
--                 , kboDetail (\"All\" :: String)
--                 ]
--      runQualysT myConf $ runKnowledgeBase opts (liftIO . print)
--    where
--      twodaysago = addUTCTime $ 2 * (-86400)
-- @

-- $exampleOption2
--
-- Print entries published between two and four days ago.
--
-- @
-- {-\# LANGUAGE OverloadedStrings \#-}
-- import Control.Monad.IO.Class (liftIO)
-- import Data.Time (getCurrentTime, addUTCTime)
-- import Qualys
--
-- myConf :: QualysConf
-- myConf = QualysConf
--     { qcPlatform = qualysUSPlatform2
--     , qcUsername = \"myuser\"
--     , qcPassword = \"mypass\"
--     , qcTimeOut  = 600 -- 10 Minutes
--     }
--
-- main :: IO ()
-- main = do
--     now <- getCurrentTime
--     let opts = [ kboPubAfter  (daysago 4 now)
--                , kboPubBefore (daysago 2 now)
--                ]
--     runQualysT myConf $ runKnowledgeBase opts (liftIO . print)
--    where
--      daysago x = addUTCTime $ x * (-86400)
-- @
