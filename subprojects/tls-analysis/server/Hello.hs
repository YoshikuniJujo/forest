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
	decode = B.evalBytableM parseClientHello
	encode = clientHelloToByteString

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
	B.encode vmjr,
	B.encode vmnr,
	B.encode r,
	B.addLen (undefined :: Word8) $ B.encode sid,
	B.addLen (undefined :: Word16) . BS.concat $ map B.encode css,
	B.addLen (undefined :: Word8) . BS.concat $ map B.encode cms,
	maybe "" (B.addLen (undefined :: Word16) . BS.concat . map B.encode) mel ]
clientHelloToByteString (ClientHelloRaw bs) = bs

data ServerHello
	= ServerHello (Word8, Word8) BS.ByteString SessionId CipherSuite
		CompressionMethod (Maybe ExtensionList)
	| ServerHelloRaw BS.ByteString
	deriving Show

instance B.Bytable ServerHello where
	decode = B.evalBytableM parseServerHello
	encode = serverHelloToByteString

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
	B.encode vmjr,
	B.encode vmnr,
	B.encode r,
	B.addLen (undefined :: Word8) $ B.encode sid,
	B.encode cs,
	compressionMethodToByteString cm,
	maybe "" (B.addLen (undefined :: Word16) . BS.concat . map B.encode) mes ]
serverHelloToByteString (ServerHelloRaw sh) = sh

data CompressionMethod
	= CompressionMethodNull
	| CompressionMethodRaw Word8
	deriving (Show, Eq)

instance B.Bytable CompressionMethod where
	decode = byteStringToCompressionMethod
	encode = compressionMethodToByteString

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
	decode = Right . SessionId
	encode (SessionId bs) = bs
