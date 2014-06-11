{-# LANGUAGE OverloadedStrings #-}

module Hello (
	Bytable(..), ContentType(..),

	ClientHello(..), ServerHello(..),
		Version(..), Random(..), SessionId(..),
		CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),
		CompressionMethod(..),

	SignatureAlgorithm(..), HashAlgorithm(..),
	takeLen', lenBodyToByteString,
 ) where

import Control.Applicative
import Control.Monad
import Data.Word
import Numeric
import qualified Data.ByteString as BS
import Extension

import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()

data ClientHello
	= ClientHello Version Random SessionId [CipherSuite]
		[CompressionMethod] (Maybe ExtensionList)
	| ClientHelloRaw BS.ByteString
	deriving Show

instance B.Bytable ClientHello where
	fromByteString = B.evalBytableM parseClientHello_
	toByteString = clientHelloToByteString

parseClientHello_ :: B.BytableM ClientHello
parseClientHello_ = do
	(pv, r, sid) <- pvrsid'
	cssl <- B.take 2
	css <- B.list cssl $ B.take 2
	cmsl <- B.take 1
	cms <- B.list cmsl $ B.take 1
	e <- B.null
	mel <- if e then return Nothing else Just <$> parseExtensionList'
	return $ ClientHello pv r sid css cms mel

parseClientHello :: ByteStringM ClientHello
parseClientHello = do
	(pv, r, sid) <- pvrsid takeBS
	css <- parse
	cms <- parse
	e <- emptyBS
	mel <- if e then return Nothing else Just <$> parseExtensionList takeBS
	return $ ClientHello pv r sid css cms mel

clientHelloToByteString :: ClientHello -> BS.ByteString
clientHelloToByteString (ClientHello pv r sid css cms mel) = BS.concat [
	toByteString' pv,
	toByteString r,
	toByteString' sid,
	toByteString css,
	toByteString cms,
	maybe "" extensionListToByteString mel
 ]
clientHelloToByteString (ClientHelloRaw bs) = bs

data ServerHello
	= ServerHello Version Random SessionId CipherSuite
		CompressionMethod (Maybe ExtensionList)
	| ServerHelloRaw BS.ByteString
	deriving Show

instance Bytable ServerHello where
	fromByteString = evalByteStringM parseServerHello
	toByteString_ = serverHelloToByteString

parseServerHello :: ByteStringM ServerHello
parseServerHello = do
	(pv, r, sid) <- pvrsid takeBS
	cs <- parse' takeBS
	cm <- parseCompressionMethod
	e <- emptyBS
	me <- if e then return Nothing else Just <$> parseExtensionList takeBS
	return $ ServerHello pv r sid cs cm me

pvrsid :: Monad m => (Int -> m BS.ByteString) -> m (Version, Random, SessionId)
pvrsid rd = (,,) `liftM` parse' rd `ap` parse' rd `ap` parse' rd

pvrsid' :: B.BytableM (Version, Random, SessionId)
pvrsid' = (,,) <$> B.take 2 <*> B.take 32 <*> (B.take =<< B.take 1)

serverHelloToByteString :: ServerHello -> BS.ByteString
serverHelloToByteString (ServerHello pv r sid cs cm mes) = BS.concat [
	toByteString' pv,
	toByteString r,
	sessionIdToByteString sid,
	toByteString' cs,
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

instance B.Bytable CompressionMethod where
	fromByteString = byteStringToCompressionMethod
	toByteString = compressionMethodToByteString

parseCompressionMethod :: ByteStringM CompressionMethod
parseCompressionMethod =
	either error id . byteStringToCompressionMethod <$> takeBS 1

byteStringToCompressionMethod :: BS.ByteString -> Either String CompressionMethod
byteStringToCompressionMethod bs = case BS.unpack bs of
	[cm] -> Right $ case cm of
		0 -> CompressionMethodNull
		_ -> CompressionMethodRaw cm
	_ -> Left "Hello.byteStringToCompressionMethod"

compressionMethodToByteString :: CompressionMethod -> BS.ByteString
compressionMethodToByteString CompressionMethodNull = "\0"
compressionMethodToByteString (CompressionMethodRaw cm) = BS.pack [cm]

data SessionId = SessionId BS.ByteString

instance Show SessionId where
	show (SessionId sid) =
		"(SessionID " ++ concatMap (`showHex` "") (BS.unpack sid) ++ ")"

sessionIdToByteString :: SessionId -> BS.ByteString
sessionIdToByteString (SessionId sid) = lenBodyToByteString 1 sid

instance Parsable' SessionId where
	parse' rd = SessionId `liftM` takeLen' rd 1
	toByteString' = sessionIdToByteString

instance B.Bytable SessionId where
	fromByteString = Right . SessionId
	toByteString (SessionId bs) = bs
