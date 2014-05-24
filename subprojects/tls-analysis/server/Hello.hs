{-# LANGUAGE OverloadedStrings #-}

module Hello (
	Parsable(..), ByteStringM,
	ClientHello(..),
	clientHelloOnlyKnownCipherSuite,
	clientHelloClientRandom, clientHelloClientVersion,
	CipherSuite(..), Random(..),
	SignatureAlgorithm(..), HashAlgorithm(..), CompressionMethod(..),
	SessionId(..), Version(..),

	ServerHello(..),
	serverHelloServerRandom, serverHelloServerVersion, serverHelloCipherSuite,

--	list1,
	evalByteStringM, lenBodyToByteString, takeBS, section',

	Parsable'(..),
 ) where

import Prelude hiding (concat, take)
import Numeric

import Control.Applicative
import Control.Monad
import Data.ByteString (ByteString, pack, unpack)
import qualified Data.ByteString as BS
import Data.Word

-- import Types

import Parts(
	Version(..), Parsable(..), CipherSuite(..), Random(..),

--	Parsable'(..),

	SignatureAlgorithm(..),
	HashAlgorithm(..),
--	Version(..),

	lenBodyToByteString, headBS,
--	list1,
	evalByteStringM,

	takeLen',
 )
import Extension

data ClientHello
	= ClientHello Version Random SessionId [CipherSuite]
		[CompressionMethod] (Maybe ExtensionList)
	| ClientHelloRaw ByteString
	deriving Show

clientHelloOnlyKnownCipherSuite :: ClientHello -> ClientHello
clientHelloOnlyKnownCipherSuite (ClientHello pv r sid css cms mel) =
	ClientHello pv r sid (TLS_RSA_WITH_AES_128_CBC_SHA : css) cms mel
clientHelloOnlyKnownCipherSuite ch = ch

clientHelloClientRandom :: ClientHello -> Maybe Random
clientHelloClientRandom (ClientHello _ r _ _ _ _) = Just r
clientHelloClientRandom _ = Nothing

clientHelloClientVersion :: ClientHello -> Maybe Version
clientHelloClientVersion (ClientHello v _ _ _ _ _) = Just v
clientHelloClientVersion _ = Nothing

instance Parsable ClientHello where
	parse = parseClientHello
	toByteString = clientHelloToByteString
	listLength _ = Nothing

parseClientHello :: ByteStringM ClientHello
parseClientHello = do
	(pv, r, sid) <- pvrsid' takeBS
	css <- parse
--	cms <- parseCompressionMethodList
	cms <- parse
	e <- emptyBS
	mel <- if e then return Nothing else Just <$> parseExtensionList takeBS
	return $ ClientHello pv r sid css cms mel

clientHelloToByteString :: ClientHello -> ByteString
clientHelloToByteString (ClientHello pv r sid css cms mel) = concat [
	toByteString pv,
	toByteString r,
	sessionIdToByteString sid,
	toByteString css,
--	compressionMethodListToByteString cms,
	toByteString cms,
	maybe "" extensionListToByteString mel
 ]
clientHelloToByteString (ClientHelloRaw bs) = bs

data ServerHello
	= ServerHello Version Random SessionId CipherSuite
		CompressionMethod (Maybe ExtensionList)
	| ServerHelloRaw ByteString
	deriving Show

instance Parsable ServerHello where
	parse = parseServerHello
	toByteString = serverHelloToByteString
	listLength _ = Nothing

serverHelloServerRandom :: ServerHello -> Maybe Random
serverHelloServerRandom (ServerHello _ r _ _ _ _) = Just r
serverHelloServerRandom _ = Nothing

serverHelloServerVersion :: ServerHello -> Maybe Version
serverHelloServerVersion (ServerHello v _ _ _ _ _) = Just v
serverHelloServerVersion _ = Nothing

serverHelloCipherSuite :: ServerHello -> Maybe CipherSuite
serverHelloCipherSuite (ServerHello _ _ _ cs _ _) = Just cs
serverHelloCipherSuite _ = Nothing

parseServerHello :: ByteStringM ServerHello
parseServerHello = do
	(pv, r, sid) <- pvrsid' takeBS
	cs <- parse' takeBS
	cm <- parseCompressionMethod
	e <- emptyBS
	me <- if e then return Nothing else Just <$> parseExtensionList takeBS
	return $ ServerHello pv r sid cs cm me

pvrsid' :: Monad m => (Int -> m BS.ByteString) -> m (Version, Random, SessionId)
pvrsid' rd = (,,) `liftM` parse' rd `ap` parse' rd `ap` parse' rd

serverHelloToByteString :: ServerHello -> ByteString
serverHelloToByteString (ServerHello pv r sid cs cm mes) = concat [
	toByteString pv,
	toByteString r,
	sessionIdToByteString sid,
	toByteString cs,
	compressionMethodToByteString cm,
	maybe "" extensionListToByteString mes
 ]
serverHelloToByteString (ServerHelloRaw sh) = sh

data CompressionMethod
	= CompressionMethodNull
	| CompressionMethodRaw Word8
	deriving (Show, Eq)

instance Parsable CompressionMethod where
	parse = parseCompressionMethod
	toByteString = compressionMethodToByteString
	listLength _ = Just 1

parseCompressionMethod :: ByteStringM CompressionMethod
parseCompressionMethod = do
	cm <- headBS
	return $ case cm of
		0 -> CompressionMethodNull
		_ -> CompressionMethodRaw cm

compressionMethodToByteString :: CompressionMethod -> ByteString
compressionMethodToByteString CompressionMethodNull = "\0"
compressionMethodToByteString (CompressionMethodRaw cm) = pack [cm]

data SessionId = SessionId ByteString

instance Show SessionId where
	show (SessionId sid) =
		"(SessionID " ++ concatMap (`showHex` "") (unpack sid) ++ ")"

sessionIdToByteString :: SessionId -> ByteString
sessionIdToByteString (SessionId sid) = lenBodyToByteString 1 sid

instance Parsable' SessionId where
	parse' rd = SessionId `liftM` takeLen' rd 1
