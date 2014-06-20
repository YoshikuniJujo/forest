{-# LANGUAGE OverloadedStrings #-}

module Hello (
	ClientHello(..), ServerHello(..),
		-- Version(..), -- Random(..),
		SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..),

	SignatureAlgorithm(..), HashAlgorithm(..), -- NamedCurve(..),
 ) where

import Control.Applicative
import Data.Word
import Numeric
import Extension

import qualified Data.ByteString as BS
import qualified Codec.Bytable as B

import CipherSuite

data ClientHello
	= ClientHello (Word8, Word8) BS.ByteString SessionId [CipherSuite]
		[CompressionMethod] (Maybe ExtensionList)
	| ClientHelloRaw BS.ByteString
	deriving Show

instance B.Bytable ClientHello where
	fromByteString = B.evalBytableM parseClientHello
	toByteString = clientHelloToByteString

parseClientHello :: B.BytableM ClientHello
parseClientHello = do
	(pv, r, sid) <- pvrsid
	cssl <- B.take 2
	css <- B.list cssl $ B.take 2
	cmsl <- B.take 1
	cms <- B.list cmsl $ B.take 1
	e <- B.null
	me <- if e then return Nothing else do
		mel <- B.take 2
		Just <$> B.list mel B.parse
	return $ ClientHello pv r sid css cms me

clientHelloToByteString :: ClientHello -> BS.ByteString
clientHelloToByteString (ClientHello (vmjr, vmnr) r sid css cms mel) = BS.concat [
	B.toByteString vmjr,
	B.toByteString vmnr,
	B.toByteString r,
	B.addLength (undefined :: Word8) $ B.toByteString sid,
	B.addLength (undefined :: Word16) . BS.concat $ map B.toByteString css,
	B.addLength (undefined :: Word8) . BS.concat $ map B.toByteString cms,
	maybe "" (B.addLength (undefined :: Word16) . BS.concat . map B.toByteString) mel ]
clientHelloToByteString (ClientHelloRaw bs) = bs

data ServerHello
	= ServerHello (Word8, Word8) BS.ByteString SessionId CipherSuite
		CompressionMethod (Maybe ExtensionList)
	| ServerHelloRaw BS.ByteString
	deriving Show

instance B.Bytable ServerHello where
	fromByteString = B.evalBytableM parseServerHello
	toByteString = serverHelloToByteString

parseServerHello :: B.BytableM ServerHello
parseServerHello = do
	(pv, r, sid) <- pvrsid
	cs <- B.take 2
	cm <- B.take 1
	e <- B.null
	me <- if e then return Nothing else do
		mel <- B.take 2
		Just <$> B.list mel B.parse
	return $ ServerHello pv r sid cs cm me

pvrsid :: B.BytableM ((Word8, Word8), BS.ByteString, SessionId)
pvrsid = (,,)
	<$> ((,) <$> B.head <*> B.head)
	<*> B.take 32
	<*> (B.take =<< B.take 1)

serverHelloToByteString :: ServerHello -> BS.ByteString
serverHelloToByteString (ServerHello (vmjr, vmnr) r sid cs cm mes) = BS.concat [
	B.toByteString vmjr,
	B.toByteString vmnr,
	B.toByteString r,
	B.addLength (undefined :: Word8) $ B.toByteString sid,
	B.toByteString cs,
	compressionMethodToByteString cm,
	maybe "" (B.addLength (undefined :: Word16) . BS.concat . map B.toByteString) mes ]
serverHelloToByteString (ServerHelloRaw sh) = sh

data CompressionMethod
	= CompressionMethodNull
	| CompressionMethodRaw Word8
	deriving (Show, Eq)

instance B.Bytable CompressionMethod where
	fromByteString = byteStringToCompressionMethod
	toByteString = compressionMethodToByteString

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

instance B.Bytable SessionId where
	fromByteString = Right . SessionId
	toByteString (SessionId bs) = bs
