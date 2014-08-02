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
--		yield $ getCaps "prof_caps_4492" Nothing v n
		process
	Just (SRPresence _ (C [(CTHash, "sha-1"), (CTVer, v), (CTNode, n)])) -> do
		yield (getCaps "prof_caps_2"
			(Just $ sender `BS.append` "@localhost/profanity") v n)
		process
	Just (SRCommon (SRIq
		Get i (Just f) (Just to) (IqDiscoInfoNode [(DTNode, n)])))
		| fromJid to == sender `BS.append` "@localhost/profanity" -> do
			yield $ resultCaps i (fromJid f) n
			yield $ SRMessageRaw Chat "prof_3" recipient message
			yield SREnd
	Just _ -> process
	_ -> return ()

begin :: ShowResponse
begin = SRCommon $ SRStream [(To, "localhost"), (Version, "1.0"), (Lang, "en")]

binds :: [ShowResponse]
binds = [
	SRCommon . SRIq Set "_xmpp_bind1" Nothing Nothing . IqBind Nothing $
		Resource "profanity",
	SRCommon $ SRIq Set "_xmpp_session1" Nothing Nothing IqSession,
	SRCommon . SRIq Get "_xmpp_roster1" Nothing Nothing $ IqRoster Nothing,
	SRPresence [(Id, "prof_presence_1")] $
		capsToCaps profanityCaps "http://www.profanity.im" ]

getCaps :: BS.ByteString -> Maybe BS.ByteString -> BS.ByteString -> BS.ByteString ->
	ShowResponse
getCaps i (Just t) v n =
	SRCommon . SRIq Get i Nothing (Just $ toJid t) $ IqCapsQuery v n
getCaps i _ v n = SRCommon . SRIq Get i Nothing Nothing $ IqCapsQuery v n

resultCaps :: BS.ByteString -> BS.ByteString -> BS.ByteString -> ShowResponse
resultCaps i t n = SRCommon $
	SRIq Result i Nothing (Just $ toJid t) (IqCapsQuery2 profanityCaps n)

sender, message :: BS.ByteString
recipient :: Jid
(sender, recipient, message) = unsafePerformIO $ do
	[s, r, m] <- getArgs
	return (BSC.pack s, Jid (BSC.pack r) "localhost" Nothing, BSC.pack m)
