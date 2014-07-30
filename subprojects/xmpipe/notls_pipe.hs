{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports, FlexibleContexts #-}

import XmppClient

import Control.Monad
import "monads-tf" Control.Monad.State
import Data.Pipe
import Data.HandleLike
import Network

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import Digest
import Caps (profanityCaps)

import System.IO.Unsafe
import System.Environment

sender, recipient, message :: BS.ByteString
[sender, recipient, message] = map BSC.pack $ unsafePerformIO getArgs

main :: IO ()
main = do
	h <- connectTo "localhost" (PortNumber 54492)
	xmpp (SHandle h) `evalStateT` ("" :: BS.ByteString)

xmpp :: (HandleLike h, MonadState (HandleMonad h),
		BS.ByteString ~ StateType (HandleMonad h)) => h -> HandleMonad h ()
xmpp h = voidM . runPipe $ input h =$= proc =$= output h

proc :: (Monad m, MonadState m, StateType m ~ BS.ByteString) =>
	Pipe ShowResponse ShowResponse m ()
proc = do
	yield SRXmlDecl
	yield $ SRStream [(To, "localhost"), (Version, "1.0"), (Lang, "en")]
	process

process :: (Monad m, MonadState m, StateType m ~ BS.ByteString) =>
	Pipe ShowResponse ShowResponse m ()
process = do
	mr <- await
	case mr of
		Just r@(SRChallengeRspauth sa) -> do
			sa0 <- lift get
			unless (sa == sa0) $ error "process: bad server"
			mapM_ yield $ mkWriteData r
			process
		Just r -> do
			let ret = mkWriteData r
			case ret of
				[SRResponse dr] -> let
					Just sret = lookup "response" $
						responseToKvs False dr in
					lift $ put sret
				_ -> return ()
			mapM_ yield ret
			process
		_ -> return ()

mkWriteData :: ShowResponse -> [ShowResponse]
mkWriteData (SRFeatures [Mechanisms ms])
	| DigestMd5 `elem` ms = [SRAuth DigestMd5]
mkWriteData (SRFeatures fs)
	| Rosterver Optional `elem` fs = [
		SRIq [(IqId, "_xmpp_bind1"), (IqType, "set")] . IqBind $
			Resource "profanity",
		SRIq [(IqId, "_xmpp_session1"), (IqType, "set")] IqSession,
		SRIq [(IqId, "_xmpp_session1"), (IqType, "set")] $ IqRoster [],
		SRPresenceRaw
			"prof_presence_1" "http://www.profanity.im" profanityCaps
		]
mkWriteData (SRChallenge r n q c _a) = (: []) $ SRResponse DR {
	drUserName = sender, drRealm = r, drPassword = "password",
	drCnonce = "00DEADBEEF00", drNonce = n, drNc = "00000001",
	drQop = q, drDigestUri = "xmpp/localhost", drCharset = c }
mkWriteData (SRChallengeRspauth _) = [SRResponseNull]
mkWriteData SRSaslSuccess =
	[SRXmlDecl, SRStream [(To, "localhost"), (Version, "1.0"), (Lang, "en")]]
mkWriteData (SRPresence _ (C [(CTHash, "sha-1"), (CTVer, v), (CTNode, n)])) =
	(: []) $ SRIq [	(IqId, "prof_caps_2"),
			(IqTo, sender `BS.append` "@localhost/profanity"),
			(IqType, "get")]
		(IqCapsQuery v n)
mkWriteData (SRIq [(IqId, i), (IqType, "get"), (IqTo, to), (IqFrom, f)]
	(IqDiscoInfoNode [(DTNode, n)]))
	| to == sender `BS.append` "@localhost/profanity" = [
		SRIq [(IqId, i), (IqTo, f), (IqType, "result")]
			(IqCapsQuery2 profanityCaps n),
		SRMessageRaw [
			(IqId, "prof_3"),
			(IqTo, recipient `BS.append` "@localhost"),
			(IqType, "chat") ] message,
		SREnd ]
mkWriteData _ = []
