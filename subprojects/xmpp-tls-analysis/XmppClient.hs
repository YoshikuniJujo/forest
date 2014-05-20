{-# LANGUAGE OverloadedStrings #-}

module XmppClient (connectSendMsg, connectSendIq) where

import Prelude hiding (drop, filter)

import Control.Monad.IO.Class
import Data.Conduit
import Data.Conduit.List
import qualified Data.Conduit.List as Cd
import Text.XML.Stream.Parse

import EventToElement
import XmppTypes
import Data.XML.Types

import qualified Data.ByteString as BS
import qualified Data.Text as T

import HandleLike

connectSendMsg :: HandleLike h => h -> T.Text -> IO ()
connectSendMsg sv msg = do
	hlPut sv $ beginDoc +++ stream
	ioSource (hlGetContent sv)
		=$= parseBytes def
		=$= eventToElementAll
		=$= Cd.map elementToStanza
		=$= runIO (responseToServer sv msg)
		=$= runIO (putStrLn . (color 31 "S: " ++) . show)
		$$ sinkNull
	putStrLn "Finished"

connectSendIq :: HandleLike h => h -> Element -> IO ()
connectSendIq sv msg = do
	hlPut sv $ beginDoc +++ stream
	ioSource (hlGetContent sv)
		=$= parseBytes def
		=$= eventToElementAll
		=$= Cd.map elementToStanza
		=$= runIO (responseToServer' sv $ makeIq msg)
		=$= runIO (putStrLn . (color 31 "S: " ++) . show)
		$$ sinkNull
	putStrLn "Finished"

ioSource :: MonadIO m => IO a -> Source m a
ioSource io = do
	x <- liftIO io
	yield x
	ioSource io

responseToServer :: HandleLike h => h -> T.Text -> Stanza -> IO ()
responseToServer sv _ (StanzaMechanismList ms)
	| DigestMd5 `elem` ms = hlPut sv . showElement . stanzaToElement $
		StanzaMechanism DigestMd5
	| otherwise = error "responseToServer: Server has no DIGEST-MD5"
responseToServer sv _ (StanzaChallenge ch@(Challenge {})) = let
	rlm = realm ch
	nnc = nonce ch
	qp = qop ch
	cs = charset ch
	alg = algorithm ch in case (qp, cs, alg) of
		("auth", "utf-8", "md5-sess") -> hlPut sv . showElement .
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
responseToServer sv _ (StanzaChallenge (ChallengeRspauth _)) =
	hlPut sv . showElement . stanzaToElement $ StanzaResponse ResponseNull
responseToServer sv _ StanzaSuccess = hlPut sv $ beginDoc +++ stream
responseToServer sv _ (StanzaFeatureList fl)
	| FeatureBind Required `elem` fl = hlPut sv . showElement . stanzaToElement $
		StanzaIq {
			iqId = "_xmpp_bind1",
			iqType = IqSet,
			iqTo = Nothing,
			iqBody = IqBodyBind [Required, BindResource "profanity"]
		 }
responseToServer sv _ (StanzaIq { iqId = "_xmpp_bind1" }) =
	hlPut sv . showElement . stanzaToElement $ StanzaIq {
		iqId = "_xmpp_session1",
		iqType = IqSet,
		iqTo = Nothing,
		iqBody = IqBodySession
	 }
responseToServer sv msg (StanzaIq { iqId = "_xmpp_session1" }) = do
	BS.putStrLn "\n##### HERE ####\n"
	hlPut sv . showElement . stanzaToElement $ StanzaMessage {
		messageType = "chat",
		messageId = "yoshikuni1",
		messageFrom = Nothing,
		messageTo = Just "yoshio@localhost",
		messageBody = [NodeElement $
			Element (Name "body" (Just "jabber:client") Nothing) [] [
				NodeContent $ ContentText ("message: " `T.append` msg)
			 ]
		 ]
	 }
	hlPut sv "</stream:stream>"
responseToServer _ _ _ = return ()

beginDoc, stream :: BS.ByteString
beginDoc = "<?xml version=\"1.0\"?>"
stream = "<stream:stream to=\"localhost\" xml:lang=\"en\" version=\"1.0\" " +++
	"xmlns=\"jabber:client\" " +++
	"xmlns:stream=\"http://etherx.jabber.org/streams\">"

runIO :: (Monad m, MonadIO m) => (a -> IO ()) -> Conduit a m a
runIO io = do
	mx <- await
	maybe (return ()) (\x -> liftIO (io x) >> yield x) mx
	runIO io

color :: Int -> String -> String
color clr str = "\x1b[" ++ show clr ++ "m" ++ str ++ "\x1b[39m"

(+++) :: BS.ByteString -> BS.ByteString -> BS.ByteString
(+++) = BS.append

makeIq :: Element -> Stanza
makeIq msg = StanzaIq {
	iqId = "hogeru",
	iqType = IqGet,
	iqTo = Just "yoshio@localhost",
	iqBody = IqBodyRaw msg
 }

responseToServer' :: HandleLike h => h -> Stanza -> Stanza -> IO ()
responseToServer' sv _ (StanzaMechanismList ms)
	| DigestMd5 `elem` ms = hlPut sv . showElement . stanzaToElement $
		StanzaMechanism DigestMd5
	| otherwise = error "responseToServer: Server has no DIGEST-MD5"
responseToServer' sv _ (StanzaChallenge ch@(Challenge {})) = let
	rlm = realm ch
	nnc = nonce ch
	qp = qop ch
	cs = charset ch
	alg = algorithm ch in case (qp, cs, alg) of
		("auth", "utf-8", "md5-sess") -> hlPut sv . showElement .
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
		_ -> error "responseToServer': not implemented"
responseToServer' sv _ (StanzaChallenge (ChallengeRspauth _)) =
	hlPut sv . showElement . stanzaToElement $ StanzaResponse ResponseNull
responseToServer' sv _ StanzaSuccess = hlPut sv $ beginDoc +++ stream
responseToServer' sv _ (StanzaFeatureList fl)
	| FeatureBind Required `elem` fl = hlPut sv . showElement . stanzaToElement $
		StanzaIq {
			iqId = "_xmpp_bind1",
			iqType = IqSet,
			iqTo = Nothing,
			iqBody = IqBodyBind [Required, BindResource "profanity"]
		 }
responseToServer' sv _ (StanzaIq { iqId = "_xmpp_bind1" }) =
	hlPut sv . showElement . stanzaToElement $ StanzaIq {
		iqId = "_xmpp_session1",
		iqType = IqSet,
		iqTo = Nothing,
		iqBody = IqBodySession
	 }
responseToServer' sv msg (StanzaIq { iqId = "_xmpp_session1" }) = do
	BS.putStrLn ""
	BS.putStr . showElement $ stanzaToElement msg
	BS.putStrLn ""
	hlPut sv . showElement $ stanzaToElement msg
	hlPut sv "</stream:stream>"
responseToServer' _ _ _ = return ()
