{-# LANGUAGE TupleSections #-}

module FromID (convertOutput) where

import Parser
import Output
import Control.Applicative
import Data.Maybe

fromID :: String -> String -> Maybe String
fromID tbl i = lookup i (map parseItemList $ lines tbl)

convertOutput :: String -> Output -> Output
convertOutput tbl (d, i) = fromJust $ (d ,) <$> fromID tbl i
