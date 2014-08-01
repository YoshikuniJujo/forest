{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports, FlexibleContexts #-}

import Debug.Trace

import "monads-tf" Control.Monad.State
import Data.List
import Data.Pipe
import Data.HandleLike
import System.Environment
import System.IO.Unsafe
import Network

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import XmppClient
import Caps (profanityCaps)

main :: IO ()
main = connectTo "localhost" (PortNumber 5222) >>= \h ->
	xmpp (SHandle h) `evalStateT` ("" :: BS.ByteString)

xmpp :: (HandleLike h, MonadState (HandleMonad h),
		BS.ByteString ~ StateType (HandleMonad h)) => h -> HandleMonad h ()
xmpp h = voidM . runPipe $ input h =$= proc =$= output h

proc :: (Monad m, MonadState m, StateType m ~ BS.ByteString) =>
	Pipe ShowResponse ShowResponse m ()
proc = yield (SRCommon SRXmlDecl)
	>> yield (SRCommon $ SRStream [(To, "localhost"), (Version, "1.0"), (Lang, "en")])
	>> process

process :: (Monad m, MonadState m, StateType m ~ BS.ByteString) =>
	Pipe ShowResponse ShowResponse m ()
process = await >>= \mr -> case mr of
	Just (SRCommon (SRFeatures [Mechanisms ms]))
		| DigestMd5 `elem` ms -> digestMd5 sender >> process
	Just (SRCommon SRSaslSuccess) -> mapM_ yield [SRCommon SRXmlDecl, begin] >> process
	Just (SRCommon (SRFeatures fs)) -> do
		trace "HERE" (return ())
		let Just Caps { cnode = n, cver = v } = find isCaps fs
		trace (show $ (n, v)) (return ())
		mapM_ yield binds
--		yield $ getCaps "prof_caps_4492" "localhost" v n
		process
	Just (SRPresence _ (C [(CTHash, "sha-1"), (CTVer, v), (CTNode, n)])) -> do
		yield (getCaps "prof_caps_2"
			(sender `BS.append` "@localhost/profanity") v n)
		process
	Just (SRIq Get i [(IqTo, to), (IqFrom, f)] (IqDiscoInfoNode [(DTNode, n)]))
		| to == sender `BS.append` "@localhost/profanity" -> do
			yield $ resultCaps i f n
			yield $ SRMessageRaw Chat "prof_3" recipient message
			yield SREnd
	Just _ -> process
	_ -> return ()

begin :: ShowResponse
begin = SRCommon $ SRStream [(To, "localhost"), (Version, "1.0"), (Lang, "en")]

binds :: [ShowResponse]
binds = [
	SRIq Set "_xmpp_bind1" [] . IqBind $ Resource "profanity",
	SRIq Set "_xmpp_session1" [] IqSession,
	SRIq Get "_xmpp_roster1" [] $ IqRoster [],
	SRPresenceRaw "prof_presence_1" "http://www.profanity.im" profanityCaps ]

getCaps :: BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString ->
	ShowResponse
getCaps i t v n = SRIq Get i [(IqTo, t)] $ IqCapsQuery v n

resultCaps :: BS.ByteString -> BS.ByteString -> BS.ByteString -> ShowResponse
resultCaps i t n = SRIq Result i [(IqTo, t)] (IqCapsQuery2 profanityCaps n)

sender, message :: BS.ByteString
recipient :: Jid
(sender, recipient, message) = unsafePerformIO $ do
	[s, r, m] <- getArgs
	return (BSC.pack s, Jid (BSC.pack r) "localhost" Nothing, BSC.pack m)
