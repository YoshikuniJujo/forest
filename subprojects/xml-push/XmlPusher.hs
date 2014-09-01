{-# LANGUAGE TypeFamilies, FlexibleContexts #-}

module XmlPusher (
	XmlPusher(..)
	) where

import Control.Monad.Base
import Control.Monad.Trans.Control
import Data.HandleLike
import Data.Pipe
import Text.XML.Pipe
import Network.PeyoTLS.Client

class XmlPusher xp where
	type PusherArg xp
	type NumOfHandle xp :: * -> *
	generate :: (ValidateHandle h, MonadBaseControl IO (HandleMonad h)) =>
		NumOfHandle xp h -> PusherArg xp -> HandleMonad h (xp h)
	readFrom :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe (Maybe XmlNode) () (HandleMonad h) ()
