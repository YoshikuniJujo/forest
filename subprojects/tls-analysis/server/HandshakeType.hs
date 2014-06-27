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
	ServerHelloDone(..), ClientKeyExchange(..), Epms(..),
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
	= HClientHello ClientHello           | HServerHello ServerHello
	| HCertificate X509.CertificateChain | HServerKeyEx BS.ByteString
	| HCertificateReq CertificateRequest | HServerHelloDone
	| HCertVerify DigitallySigned        | HClientKeyEx ClientKeyExchange
	| HFinished BS.ByteString            | HRaw Type BS.ByteString
	deriving Show

instance B.Bytable Handshake where
	decode = B.evalBytableM B.parse; encode = encodeH

instance B.Parsable Handshake where
	parse = do
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
encodeH (HClientHello ch) = encodeH . HRaw TClientHello $ B.encode ch
encodeH (HServerHello sh) = encodeH . HRaw TServerHello $ B.encode sh
encodeH (HCertificate crts) = encodeH . HRaw TCertificate $ B.encode crts
encodeH (HServerKeyEx ske) = encodeH $ HRaw TServerKeyEx ske
encodeH (HCertificateReq cr) = encodeH . HRaw TCertificateReq $ B.encode cr
encodeH HServerHelloDone = encodeH $ HRaw TServerHelloDone ""
encodeH (HCertVerify ds) = encodeH . HRaw TCertVerify $ B.encode ds
encodeH (HClientKeyEx epms) = encodeH . HRaw TClientKeyEx $ B.encode epms
encodeH (HFinished bs) = encodeH $ HRaw TFinished bs
encodeH (HRaw t bs) = B.encode t `BS.append` B.addLen (undefined :: Word24) bs

class HandshakeItem hi where
	fromHandshake :: Handshake -> Maybe hi;
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
	toHandshake = HServerKeyEx . B.encode

instance B.Bytable ServerKeyExchange where
	decode = undefined
	encode (ServerKeyEx ps pv ha sa sn) = BS.concat [
		ps, pv, B.encode ha, B.encode sa,
		B.addLen (undefined :: Word16) sn ]

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

data Epms = Epms BS.ByteString

instance HandshakeItem Epms where
	fromHandshake (HClientKeyEx cke) = ckeToEpms cke
	fromHandshake _ = Nothing
	toHandshake = HClientKeyEx . epmsToCke

ckeToEpms :: ClientKeyExchange -> Maybe Epms
ckeToEpms (ClientKeyExchange cke) = case B.runBytableM (B.take =<< B.take 2) cke of
	Right (e, "") -> Just $ Epms e
	_ -> Nothing

epmsToCke :: Epms -> ClientKeyExchange
epmsToCke (Epms epms) = ClientKeyExchange $ B.addLen (undefined :: Word16) epms

data Finished = Finished BS.ByteString deriving (Show, Eq)

instance HandshakeItem Finished where
	fromHandshake (HFinished f) = Just $ Finished f
	fromHandshake _ = Nothing
	toHandshake (Finished f) = HFinished f

data ServerHelloDone = ServerHelloDone deriving Show

data Type
	= TClientHello | TServerHello
	| TCertificate | TServerKeyEx | TCertificateReq | TServerHelloDone
	| TCertVerify  | TClientKeyEx | TFinished       | TRaw Word8
	deriving Show

instance B.Bytable Type where
	decode bs = case BS.unpack bs of
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
		_ -> Left "Handshake.decodeT"
	encode TClientHello = BS.pack [1]
	encode TServerHello = BS.pack [2]
	encode TCertificate = BS.pack [11]
	encode TServerKeyEx = BS.pack [12]
	encode TCertificateReq = BS.pack [13]
	encode TServerHelloDone = BS.pack [14]
	encode TCertVerify = BS.pack [15]
	encode TClientKeyEx = BS.pack [16]
	encode TFinished = BS.pack [20]
	encode (TRaw w) = BS.pack [w]
