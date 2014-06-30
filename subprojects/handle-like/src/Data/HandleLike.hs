{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts #-}

module Data.HandleLike (HandleLike(..), hlPutStrLn) where

import Data.HandleLike.Class
import Data.HandleLike.Instance.Handle ()
