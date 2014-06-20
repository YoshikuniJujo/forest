{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module HandshakeType (
	Handshake(..), HandshakeItem(..),
		ServerKeyExchange(..), ServerHelloDone(..), Finished(..),
	ClientHello(..), ServerHello(..),
		SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..),
	CertificateRequest(..),
		ClientCertificateType(..),
		SignatureAlgorithm(..), HashAlgorithm(..),
	ClientKeyExchange(..),
	DigitallySigned(..),
	NamedCurve(..), secp256r1, dhparams3072,
) where

import Control.Applicative

import qualified Codec.Bytable as B

import Data.Word (Word8, Word16)
import Data.Word.Word24
import qualified Data.ByteString as BS

import Hello
--	(Bytable(..), ClientHello(..), ServerHello(..), takeLen', lenBodyToByteString)
import Certificate
import qualified Data.X509 as X509

import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.Types.PubKey.DH as DH

import Numeric

data Handshake
	= HandshakeClientHello ClientHello
	| HandshakeServerHello ServerHello
	| HandshakeCertificate X509.CertificateChain
	| HandshakeServerKeyExchange BS.ByteString
	| HandshakeCertificateRequest CertificateRequest
	| HandshakeServerHelloDone
	| HandshakeCertificateVerify DigitallySigned
	| HandshakeClientKeyExchange ClientKeyExchange
	| HandshakeFinished BS.ByteString
	| HandshakeRaw HandshakeType BS.ByteString
	deriving Show

class HandshakeItem ht where
	fromHandshake :: Handshake -> Maybe ht
	toHandshake :: ht -> Handshake

data Finished = Finished BS.ByteString deriving (Show, Eq)

data ServerKeyExchange
	= ServerKeyExchange BS.ByteString BS.ByteString
		HashAlgorithm SignatureAlgorithm BS.ByteString deriving Show

instance B.Bytable ServerKeyExchange where
	fromByteString = undefined
	toByteString = serverKeyExchangeToByteString

data ServerHelloDone = ServerHelloDone deriving Show

serverKeyExchangeToByteString :: ServerKeyExchange -> BS.ByteString
serverKeyExchangeToByteString
	(ServerKeyExchange params dhYs hashA sigA sn) =
	BS.concat [
		params, dhYs, B.toByteString hashA, B.toByteString sigA,
		B.addLength (undefined :: Word16) sn ]

instance HandshakeItem Finished where
	fromHandshake (HandshakeFinished f) = Just $ Finished f
	fromHandshake _ = Nothing
	toHandshake (Finished f) = HandshakeFinished f

instance HandshakeItem ClientHello where
	fromHandshake (HandshakeClientHello ch) = Just ch
	fromHandshake _ = Nothing
	toHandshake = HandshakeClientHello

instance HandshakeItem ServerHello where
	fromHandshake (HandshakeServerHello sh) = Just sh
	fromHandshake _ = Nothing
	toHandshake = HandshakeServerHello

instance HandshakeItem X509.CertificateChain where
	fromHandshake (HandshakeCertificate cc) = Just cc
	fromHandshake _ = Nothing
	toHandshake = HandshakeCertificate

instance HandshakeItem ServerKeyExchange where
	fromHandshake = undefined
	toHandshake = HandshakeServerKeyExchange . B.toByteString

instance HandshakeItem CertificateRequest where
	fromHandshake (HandshakeCertificateRequest cr) = Just cr
	fromHandshake _ = Nothing
	toHandshake = HandshakeCertificateRequest

instance HandshakeItem ServerHelloDone where
	fromHandshake HandshakeServerHelloDone = Just ServerHelloDone
	fromHandshake _ = Nothing
	toHandshake _ = HandshakeServerHelloDone

instance HandshakeItem ClientKeyExchange where
	fromHandshake (HandshakeClientKeyExchange cke) = Just cke
	fromHandshake _ = Nothing
	toHandshake = HandshakeClientKeyExchange

instance HandshakeItem DigitallySigned where
	fromHandshake (HandshakeCertificateVerify ds) = Just ds
	fromHandshake _ = Nothing
	toHandshake = HandshakeCertificateVerify

instance B.Bytable Handshake where
	fromByteString = B.evalBytableM B.parse
	toByteString = handshakeToByteString

instance B.Parsable Handshake where
	parse = parseHandshake

parseHandshake :: B.BytableM Handshake
parseHandshake = do
	t <- B.take 1
	len <- B.take 3
	case t of
		HandshakeTypeClientHello -> HandshakeClientHello <$> B.take len
		HandshakeTypeServerHello -> HandshakeServerHello <$> B.take len
		HandshakeTypeCertificate -> HandshakeCertificate <$> B.take len
		HandshakeTypeServerKeyExchange ->
			HandshakeServerKeyExchange <$> B.take len
		HandshakeTypeCertificateRequest ->
			HandshakeCertificateRequest <$> B.take len
		HandshakeTypeServerHelloDone -> return HandshakeServerHelloDone
		HandshakeTypeCertificateVerify ->
			HandshakeCertificateVerify <$> B.take len
		HandshakeTypeClientKeyExchange ->
			HandshakeClientKeyExchange <$> B.take len
		HandshakeTypeFinished -> HandshakeFinished <$> B.take len
		_ -> HandshakeRaw t <$> B.take len

handshakeToByteString :: Handshake -> BS.ByteString
handshakeToByteString (HandshakeClientHello ch) = handshakeToByteString .
	HandshakeRaw HandshakeTypeClientHello $ B.toByteString ch
handshakeToByteString (HandshakeServerHello sh) = handshakeToByteString .
	HandshakeRaw HandshakeTypeServerHello $ B.toByteString sh
handshakeToByteString (HandshakeCertificate crts) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificate $ B.toByteString crts
handshakeToByteString (HandshakeServerKeyExchange ske) = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerKeyExchange ske
handshakeToByteString (HandshakeCertificateRequest cr) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificateRequest $ B.toByteString cr
handshakeToByteString HandshakeServerHelloDone = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerHelloDone ""
handshakeToByteString (HandshakeCertificateVerify ds) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificateVerify $ B.toByteString ds
handshakeToByteString (HandshakeClientKeyExchange epms) = handshakeToByteString .
	HandshakeRaw HandshakeTypeClientKeyExchange $ B.toByteString epms
handshakeToByteString (HandshakeFinished bs) = handshakeToByteString $
	HandshakeRaw HandshakeTypeFinished bs
handshakeToByteString (HandshakeRaw mt bs) =
	B.toByteString mt `BS.append` B.addLength (undefined :: Word24) bs

data HandshakeType
	= HandshakeTypeClientHello
	| HandshakeTypeServerHello
	| HandshakeTypeCertificate
	| HandshakeTypeServerKeyExchange
	| HandshakeTypeCertificateRequest
	| HandshakeTypeServerHelloDone
	| HandshakeTypeCertificateVerify
	| HandshakeTypeClientKeyExchange
	| HandshakeTypeFinished
	| HandshakeTypeRaw Word8
	deriving Show

instance B.Bytable HandshakeType where
	fromByteString = byteStringToHandshakeType
	toByteString = handshakeTypeToByteString

byteStringToHandshakeType :: BS.ByteString -> Either String HandshakeType
byteStringToHandshakeType bs = case BS.unpack bs of
	[1] -> Right HandshakeTypeClientHello
	[2] -> Right HandshakeTypeServerHello
	[11] -> Right HandshakeTypeCertificate
	[12] -> Right HandshakeTypeServerKeyExchange
	[13] -> Right HandshakeTypeCertificateRequest
	[14] -> Right HandshakeTypeServerHelloDone
	[15] -> Right HandshakeTypeCertificateVerify
	[16] -> Right HandshakeTypeClientKeyExchange
	[20] -> Right HandshakeTypeFinished
	[ht] -> Right $ HandshakeTypeRaw ht
	_ -> Left "Handshake.byteStringToHandshakeType"

handshakeTypeToByteString :: HandshakeType -> BS.ByteString
handshakeTypeToByteString HandshakeTypeClientHello = BS.pack [1]
handshakeTypeToByteString HandshakeTypeServerHello = BS.pack [2]
handshakeTypeToByteString HandshakeTypeCertificate = BS.pack [11]
handshakeTypeToByteString HandshakeTypeServerKeyExchange = BS.pack [12]
handshakeTypeToByteString HandshakeTypeCertificateRequest = BS.pack [13]
handshakeTypeToByteString HandshakeTypeServerHelloDone = BS.pack [14]
handshakeTypeToByteString HandshakeTypeCertificateVerify = BS.pack [15]
handshakeTypeToByteString HandshakeTypeClientKeyExchange = BS.pack [16]
handshakeTypeToByteString HandshakeTypeFinished = BS.pack [20]
handshakeTypeToByteString (HandshakeTypeRaw w) = BS.pack [w]

instance B.Bytable DH.Params where
	fromByteString = B.evalBytableM $ DH.Params <$> B.take 2 <*> B.take 2
	toByteString (DH.Params dhP dhG) = BS.concat [
		B.addLength (undefined :: Word16) $ B.toByteString dhP,
		B.addLength (undefined :: Word16) $ B.toByteString dhG ]

instance B.Bytable DH.PublicNumber where
	fromByteString = B.evalBytableM $ fromInteger <$> (B.take =<< B.take 2)
	toByteString = B.addLength (undefined :: Word16) .
		B.toByteString . \(DH.PublicNumber pn) -> pn

instance B.Bytable ECC.Point where
	fromByteString bs = case BS.uncons $ BS.tail bs of
		Just (4, rest) -> Right $ let (x, y) = BS.splitAt 32 rest in
			ECC.Point	(either error id $ B.fromByteString x)
					(either error id $ B.fromByteString y)
		_ -> Left "KeyAgreement.hs: ECC.Point.fromByteString"
	toByteString (ECC.Point x y) = B.addLength (undefined :: Word8) .
		BS.cons 4 $ BS.append (B.toByteString x) (B.toByteString y)
	toByteString ECC.PointO = error "KeyAgreement.hs: EC.Point.toByteString"

data EcCurveType = ExplicitPrime | ExplicitChar2 | NamedCurve | EcCurveTypeRaw Word8
	deriving Show

instance B.Bytable EcCurveType where
	fromByteString = undefined
	toByteString ExplicitPrime = BS.pack [1]
	toByteString ExplicitChar2 = BS.pack [2]
	toByteString NamedCurve = BS.pack [3]
	toByteString (EcCurveTypeRaw w) = BS.pack [w]

instance B.Bytable ECC.Curve where
	fromByteString = undefined
	toByteString = encodeCurve

encodeCurve :: ECC.Curve -> BS.ByteString
encodeCurve c
	| c == secp256r1 =
		B.toByteString NamedCurve `BS.append` B.toByteString Secp256r1
	| otherwise = error "TlsServer.encodeCurve: not implemented"

secp256r1 :: ECC.Curve
secp256r1 = ECC.CurveFP $ ECC.CurvePrime p (ECC.CurveCommon a b g n h)
	where
	p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
	a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
	b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
	g = ECC.Point gx gy
	gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
	gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
	n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
	h = 0x01

dhparams3072 :: DH.Params
dhparams3072 = DH.Params p 2
	where [(p, "")] = readHex $
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1" ++
		"29024e088a67cc74020bbea63b139b22514a08798e3404dd" ++
		"ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245" ++
		"e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" ++
		"ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d" ++
		"c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f" ++
		"83655d23dca3ad961c62f356208552bb9ed529077096966d" ++
		"670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" ++
		"e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9" ++
		"de2bcbf6955817183995497cea956ae515d2261898fa0510" ++
		"15728e5a8aaac42dad33170d04507a33a85521abdf1cba64" ++
		"ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7" ++
		"abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b" ++
		"f12ffa06d98a0864d87602733ec86a64521f2b18177b200c" ++
		"bbe117577a615d6c770988c0bad946e208e24fa074e5ab31" ++
		"43db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"
