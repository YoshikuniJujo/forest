{-# LANGUAGE TupleSections, TypeFamilies, FlexibleContexts,
	PackageImports #-}

module HttpPush (
	HttpPush,
	) where

import Control.Applicative
import "monads-tf" Control.Monad.Trans
import Control.Monad.Base
import Control.Concurrent.STM
import Data.HandleLike
import Data.Pipe
import Data.Pipe.TChan
import Text.XML.Pipe

import XmlPusher

data HttpPush h = HttpPush {
	needReply :: TVar Bool,
	clientReadChan :: TChan (XmlNode, Bool),
	clientWriteChan :: TChan (Maybe XmlNode),
	serverReadChan :: TChan (XmlNode, Bool),
	serverWriteChan :: TChan (Maybe XmlNode) }

instance XmlPusher HttpPush where
	type NumOfHandle HttpPush = Two
	type PusherArg HttpPush = ()
	generate (Two ch sh) () = makeHttpPush ch sh
	readFrom hp = fromTChans [clientReadChan hp, serverReadChan hp] =$=
		setNeedReply (needReply hp)
	writeTo hp = (convert (((), ) . (fst <$>)) =$=) . toTChansM $ do
		nr <- liftBase . atomically . readTVar $ needReply hp
		liftBase . atomically $ writeTVar (needReply hp) False
		return [
			(const nr, serverWriteChan hp),
			(const True, clientWriteChan hp) ]

setNeedReply :: MonadBase IO m => TVar Bool -> Pipe (a, Bool) a m ()
setNeedReply nr = await >>= maybe (return ()) (\(x, b) ->
	lift (liftBase . atomically $ writeTVar nr b) >> yield x >> setNeedReply nr)

makeHttpPush :: MonadBase IO (HandleMonad h) => h -> h -> HandleMonad h (HttpPush h)
makeHttpPush ch sh = do
	v <- liftBase . atomically $ newTVar False
	(ci, co) <- clientC ch
	(si, so) <- talk sh
	return $ HttpPush v ci co si so

clientC = undefined

talk = undefined
