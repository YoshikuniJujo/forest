{-# LANGUAGE OverloadedStrings #-}

import Prelude hiding (drop, filter)

import System.IO
import System.Exit
import Control.Monad.IO.Class
import Data.Conduit
import Data.Conduit.List
import qualified Data.Conduit.List as Cd
import Data.Conduit.Binary hiding (drop, isolate)
import Text.XML.Stream.Parse
import Network

import EventToElement
import XmppTypes
import Data.XML.Types

import qualified Data.ByteString.Char8 as BSC
import qualified Data.Text as T
import qualified Data.ByteString.Base64 as B64

main :: IO ()
main = do
	h <- connectTo "localhost" (PortNumber 54492)
	hPutStr h $ beginDoc ++ stream
	sourceHandle h
		=$= parseBytes def
		=$= checkEnd h
		=$= eventToElementAll
		=$= Cd.map elementToStanza
		=$= runIO (responseToServer h)
		=$= runIO (putStrLn . (color 31 "S: " ++) . show)
		$$ sinkNull
	putStrLn "Finished"

checkEnd :: Handle -> Conduit Event IO Event
checkEnd h = do
	me <- await
	liftIO $ print me
	case me of
		Just (EventEndElement (Name "stream" _ _)) -> do
			liftIO $ do
				putStrLn "End stream"
				hClose h
				exitSuccess
		Just e -> do
			yield e
			checkEnd h
		_ -> return ()

responseToServer :: Handle -> Stanza -> IO ()
responseToServer sv (StanzaMechanismList ms)
	| DigestMd5 `elem` ms = hPutStr sv . showElement . stanzaToElement $
		StanzaMechanism DigestMd5
	| otherwise = error "responseToServer: Server has no DIGEST-MD5"
responseToServer sv (StanzaChallenge ch@(Challenge {})) = let
	rlm = realm ch
	nnc = nonce ch
	qp = qop ch
	cs = charset ch
	alg = algorithm ch in case (qp, cs, alg) of
		("auth", "utf-8", "md5-sess") -> hPutStr sv . showElement .
			stanzaToElement $ StanzaResponse Response {
				rUsername = "yoshikuni",
				rRealm = rlm,
				rPassword = "password",
				rCnonce = "00EADBEEF00",
				rNonce = nnc,
				rNc = "00000001",
				rQop = qp,
				rDigestUri = "xmpp/localhost",
				rCharset = cs
			 }
		_ -> error "responseToServer: not implemented"
responseToServer sv (StanzaChallenge (ChallengeRspauth _)) =
	hPutStr sv . showElement . stanzaToElement $ StanzaResponse ResponseNull
responseToServer sv StanzaSuccess = hPutStr sv $ beginDoc ++ stream
responseToServer sv (StanzaFeatureList fl)
	| FeatureBind Required `elem` fl = hPutStr sv . showElement . stanzaToElement $
		StanzaIq {
			iqId = "_xmpp_bind1",
			iqType = IqSet,
			iqTo = Nothing,
			iqBody = IqBodyBind [Required, BindResource "profanity"]
		 }
responseToServer sv (StanzaIq { iqId = "_xmpp_bind1" }) =
	hPutStr sv . showElement . stanzaToElement $ StanzaIq {
		iqId = "_xmpp_session1",
		iqType = IqSet,
		iqTo = Nothing,
		iqBody = IqBodySession
	 }
responseToServer sv (StanzaIq { iqId = "_xmpp_session1" }) = do
	hPutStr sv . showElement . stanzaToElement $ StanzaMessage {
		messageType = "chat",
		messageId = "yoshikuni1",
		messageFrom = Nothing,
		messageTo = Just "yoshio@localhost",
		messageBody = [NodeElement $
			Element (Name "body" (Just "jabber:client") Nothing) [] [
				NodeContent $ ContentText "yoshio"
			 ]
		 ]
	 }
	hPutStr sv "</stream>"
responseToServer _ _ = return ()

beginDoc, stream, streamServer :: String
beginDoc = "<?xml version=\"1.0\"?>"
stream = "<stream:stream to=\"localhost\" xml:lang=\"en\" version=\"1.0\" " ++
	"xmlns=\"jabber:client\" " ++
	"xmlns:stream=\"http://etherx.jabber.org/streams\">"
streamServer = "<stream:stream xmlns='jabber:client' " ++
	"xmlns:stream='http://etherx.jabber.org/stream' " ++ 
	"id='hoge' from='localhost' version='1.0' xml:lang='en'>"

skip :: Monad m => Int -> Conduit a m a
skip n = drop n >> complete

complete :: Monad m => Conduit a m a
complete = do
	mx <- await
	case mx of
		Just x -> do
			yield x
			complete
		_ -> return ()

runIO :: (Monad m, MonadIO m) => (a -> IO ()) -> Conduit a m a
runIO io = do
	mx <- await
	maybe (return ()) (\x -> liftIO (io x) >> yield x) mx
	runIO io

addBegin :: Event -> String
addBegin EventBeginDocument = beginDoc
addBegin (EventBeginElement (Name "stream" _ _) _) = stream
addBegin _ = ""

addBeginServer :: Event -> String
addBeginServer EventBeginDocument = beginDoc
addBeginServer (EventBeginElement (Name "stream" _ _) _) = streamServer
addBeginServer _ = ""

normal :: Event -> Bool
normal EventBeginDocument = False
normal (EventBeginElement (Name "stream" _ _) _) = False
normal _ = True

doubleMessage :: Element -> String
doubleMessage e@(Element (Name "message" _ _) _ _) =
	showElement e ++ showElement e
doubleMessage e = showElement e

showContent :: Element -> String
showContent (Element (Name "response" _ _) _
	(NodeContent (ContentText txt) : _)) = "here: " ++ BSC.unpack
		((\(Right r) -> r) . B64.decode . BSC.pack $ T.unpack txt)
showContent e = showElement e

color :: Int -> String -> String
color clr str = "\x1b[" ++ show clr ++ "m" ++ str ++ "\x1b[39m"
