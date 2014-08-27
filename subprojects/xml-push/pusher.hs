{-# LANGUAGE TypeFamilies, FlexibleContexts, ScopedTypeVariables, PackageImports #-}

import "monads-tf" Control.Monad.Trans
import Data.Maybe
import Data.Pipe
import Data.HandleLike
import System.IO
import Text.XML.Pipe

import Control.Monad.Base
import Control.Concurrent.STM
import Network.XMPiPe.Core.C2S.Client

import qualified Data.ByteString as BS

class XmlPusher xp where
	generate :: HandleLike h => h -> HandleMonad h (xp h)
	readFrom :: xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: xp h -> Pipe XmlNode () (HandleMonad h) ()

data Xmpp h = Xmpp
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

instance XmlPusher Xmpp where
	generate = makeXmpp
	readFrom (Xmpp r _) = r
	writeTo (Xmpp _ w) = w

makeXmpp :: HandleLike h => h -> HandleMonad h (Xmpp h)
makeXmpp h = return $ Xmpp r w
	where
	r = fromHandleLike h
		=$= xmlEvent =$= convert fromJust =$= xmlNode [] >> return ()
	w = convert (xmlString . (: [])) =$= toHandleLike h

fromHandleLike :: HandleLike h => h -> Pipe () BS.ByteString (HandleMonad h) ()
fromHandleLike h = lift (hlGetContent h) >>= yield >> fromHandleLike h

toHandleLike :: HandleLike h => h -> Pipe BS.ByteString () (HandleMonad h) ()
toHandleLike h = await >>= maybe (return ()) ((>> toHandleLike h) . lift . hlPut h)

main :: IO ()
main = do
	(x :: Xmpp (ReadWrite Handle)) <- generate $ RW stdin stdout
	runPipe_ $ readFrom x =$= writeTo x

data ReadWrite h = RW h h deriving Show

instance HandleLike h => HandleLike (ReadWrite h) where
	type HandleMonad (ReadWrite h) = HandleMonad h
	hlPut (RW _ w) = hlPut w
	hlGet (RW r _) = hlGet r
	hlClose (RW r w) = hlClose r >> hlClose w
