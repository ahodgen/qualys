module Qualys.Cookbook.Options
    (
    -- * General
    -- $general

    -- * V2 Options
    -- $v2opts

    -- * V3 Options
    -- ** Filters
    -- $v3filt

    -- ** Preferences
    -- blah blah
    ) where

-- $general
--
-- In order to reflect the Qualys API documentation closely, options are
-- handled differently depending on the API called. To determine which type
-- of options to construct, take a look at the function called:
--
-- * If the function takes an argument of ['Param'] then V2 options are needed.
-- * If the function takes an argument of 'V3Options' then V3 options are
--   needed.

-- $v2opts
--
-- V2 options are constructed by functions to build a list of parameters.
-- Here is an example.
--
-- @
-- options :: [Param]
-- options = [ hldoAgIds [1,5,108]
--           , hldoShowIgs True
--           ]
-- @
--
-- The above options can also be manually constructed like this.
--
-- @
-- options :: [Param]
-- options = [ ("ag_ids",   "1,5,108")
--           , ("show_igs", "1")
--           ]
-- @

-- $v3filt
--
-- V3 Filters are constructed using a filter, an operation, and a value. The
-- filters that are valid for a call are listed in its documentation.
-- Operations are listed in "Qualys.V3api#g:1".
--
-- Here is an example of a filter:
--
-- @
-- options :: V3Options
-- options = V3Options
--    { filt =
--        [ wasFiltName `contains` \"test\"
--        , wasFiltIsScanned `equals` True
--        ]
--    }
-- @
--
-- Values given have to be valid for the type of operation requested.
-- An invalid value will produce an error like:
--
-- @
-- No instance for (Num Data.Text.Internal.Text)
--   arising from the literal ‘1’
-- In the second argument of ‘contains’, namely ‘1’
-- In the expression: wasFiltName `contains` 1
-- In the ‘filt’ field of a record
-- @
--
-- In this instance, the compiler is telling us that it expected a Text
-- value but received a numeric value.
--
-- Filters can also be manually constructed. Here is an example.
--
-- @
-- options :: V3Options
-- options = V3Options
--    { filt =
--        [ Crit { field = "name", oper = Contains, value = "example" } ]
--    }
-- @
