{-# LANGUAGE TypeFamilies, FlexibleContexts, PackageImports #-}

module XmlPusher (XmlPusher(..), Zero(..), One(..), Two(..)) where

import "monads-tf" Control.Monad.Error
import Control.Monad.Base
import Control.Monad.Trans.Control
import Data.HandleLike
import Data.Pipe
import Text.XML.Pipe
import Network.PeyoTLS.Client

class XmlPusher xp where
	type PusherArg xp
	type NumOfHandle xp :: * -> *
	generate :: (
		ValidateHandle h, MonadBaseControl IO (HandleMonad h),
		MonadError (HandleMonad h), Error (ErrorType (HandleMonad h))
		) =>
		NumOfHandle xp h -> PusherArg xp -> HandleMonad h (xp h)
	readFrom :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe XmlNode () (HandleMonad h) ()

data Zero a = Zero deriving Show
data One a = One a deriving Show
data Two a = Two a a deriving Show
