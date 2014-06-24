{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module HandshakeType (
	Handshake, HandshakeItem(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..),
	ServerKeyExchange(..),
	certificateRequest, ClientCertificateType(..),
		SignatureAlgorithm(..), HashAlgorithm(..),
	ServerHelloDone(..), ClientKeyExchange(..),
	DigitallySigned(..), Finished(..) ) where

import Control.Applicative ((<$>))
import Data.Word (Word8, Word16)
import Data.Word.Word24 (Word24)

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Codec.Bytable as B

import Hello (
	ClientHello(..), ServerHello(..), SessionId(..),
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	CompressionMethod(..), HashAlgorithm(..), SignatureAlgorithm(..) )
import Certificate (
	CertificateRequest, certificateRequest, ClientCertificateType(..),
	ClientKeyExchange(..), DigitallySigned(..) )

data Handshake
	= HClientHello ClientHello
	| HServerHello ServerHello
	| HCertificate X509.CertificateChain
	| HServerKeyEx BS.ByteString
	| HCertificateReq CertificateRequest
	| HServerHelloDone
	| HCertVerify DigitallySigned
	| HClientKeyEx ClientKeyExchange
	| HFinished BS.ByteString
	| HRaw Type BS.ByteString
	deriving Show

instance B.Bytable Handshake where
	fromByteString = B.evalBytableM B.parse
	toByteString = encodeH

instance B.Parsable Handshake where
	parse = parseHandshake

parseHandshake :: B.BytableM Handshake
parseHandshake = do
	t <- B.take 1
	len <- B.take 3
	case t of
		TClientHello -> HClientHello <$> B.take len
		TServerHello -> HServerHello <$> B.take len
		TCertificate -> HCertificate <$> B.take len
		TServerKeyEx -> HServerKeyEx <$> B.take len
		TCertificateReq -> HCertificateReq <$> B.take len
		TServerHelloDone -> let 0 = len in return HServerHelloDone
		TCertVerify -> HCertVerify <$> B.take len
		TClientKeyEx -> HClientKeyEx <$> B.take len
		TFinished -> HFinished <$> B.take len
		_ -> HRaw t <$> B.take len

encodeH :: Handshake -> BS.ByteString
encodeH (HClientHello ch) = encodeH .  HRaw TClientHello $ B.toByteString ch
encodeH (HServerHello sh) = encodeH . HRaw TServerHello $ B.toByteString sh
encodeH (HCertificate crts) = encodeH . HRaw TCertificate $ B.toByteString crts
encodeH (HServerKeyEx ske) = encodeH $ HRaw TServerKeyEx ske
encodeH (HCertificateReq cr) = encodeH . HRaw TCertificateReq $ B.toByteString cr
encodeH HServerHelloDone = encodeH $ HRaw TServerHelloDone ""
encodeH (HCertVerify ds) = encodeH . HRaw TCertVerify $ B.toByteString ds
encodeH (HClientKeyEx epms) = encodeH . HRaw TClientKeyEx $ B.toByteString epms
encodeH (HFinished bs) = encodeH $ HRaw TFinished bs
encodeH (HRaw t bs) = B.toByteString t `BS.append` B.addLength (undefined :: Word24) bs

class HandshakeItem hi where
	fromHandshake :: Handshake -> Maybe hi
	toHandshake :: hi -> Handshake

instance HandshakeItem ClientHello where
	fromHandshake (HClientHello ch) = Just ch
	fromHandshake _ = Nothing
	toHandshake = HClientHello

instance HandshakeItem ServerHello where
	fromHandshake (HServerHello sh) = Just sh
	fromHandshake _ = Nothing
	toHandshake = HServerHello

instance HandshakeItem X509.CertificateChain where
	fromHandshake (HCertificate cc) = Just cc
	fromHandshake _ = Nothing
	toHandshake = HCertificate

data ServerKeyExchange = ServerKeyEx BS.ByteString BS.ByteString
	HashAlgorithm SignatureAlgorithm BS.ByteString deriving Show

instance HandshakeItem ServerKeyExchange where
	fromHandshake = undefined
	toHandshake = HServerKeyEx . B.toByteString

instance B.Bytable ServerKeyExchange where
	fromByteString = undefined
	toByteString = serverKeyExchangeToByteString

serverKeyExchangeToByteString :: ServerKeyExchange -> BS.ByteString
serverKeyExchangeToByteString
	(ServerKeyEx params dhYs hashA sigA sn) =
	BS.concat [
		params, dhYs, B.toByteString hashA, B.toByteString sigA,
		B.addLength (undefined :: Word16) sn ]

instance HandshakeItem CertificateRequest where
	fromHandshake (HCertificateReq cr) = Just cr
	fromHandshake _ = Nothing
	toHandshake = HCertificateReq

instance HandshakeItem ServerHelloDone where
	fromHandshake HServerHelloDone = Just ServerHelloDone
	fromHandshake _ = Nothing
	toHandshake _ = HServerHelloDone

instance HandshakeItem DigitallySigned where
	fromHandshake (HCertVerify ds) = Just ds
	fromHandshake _ = Nothing
	toHandshake = HCertVerify

instance HandshakeItem ClientKeyExchange where
	fromHandshake (HClientKeyEx cke) = Just cke
	fromHandshake _ = Nothing
	toHandshake = HClientKeyEx

data Finished = Finished BS.ByteString deriving (Show, Eq)

instance HandshakeItem Finished where
	fromHandshake (HFinished f) = Just $ Finished f
	fromHandshake _ = Nothing
	toHandshake (Finished f) = HFinished f

data ServerHelloDone = ServerHelloDone deriving Show

data Type
	= TClientHello
	| TServerHello
	| TCertificate
	| TServerKeyEx
	| TCertificateReq
	| TServerHelloDone
	| TCertVerify
	| TClientKeyEx
	| TFinished
	| TRaw Word8
	deriving Show

instance B.Bytable Type where
	fromByteString = byteStringToType
	toByteString = typeToByteString

byteStringToType :: BS.ByteString -> Either String Type
byteStringToType bs = case BS.unpack bs of
	[1] -> Right TClientHello
	[2] -> Right TServerHello
	[11] -> Right TCertificate
	[12] -> Right TServerKeyEx
	[13] -> Right TCertificateReq
	[14] -> Right TServerHelloDone
	[15] -> Right TCertVerify
	[16] -> Right TClientKeyEx
	[20] -> Right TFinished
	[ht] -> Right $ TRaw ht
	_ -> Left "Handshake.byteStringToType"

typeToByteString :: Type -> BS.ByteString
typeToByteString TClientHello = BS.pack [1]
typeToByteString TServerHello = BS.pack [2]
typeToByteString TCertificate = BS.pack [11]
typeToByteString TServerKeyEx = BS.pack [12]
typeToByteString TCertificateReq = BS.pack [13]
typeToByteString TServerHelloDone = BS.pack [14]
typeToByteString TCertVerify = BS.pack [15]
typeToByteString TClientKeyEx = BS.pack [16]
typeToByteString TFinished = BS.pack [20]
typeToByteString (TRaw w) = BS.pack [w]
