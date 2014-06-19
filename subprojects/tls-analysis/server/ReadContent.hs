{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports,
	TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module ReadContent (
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	ValidateHandle(..),
	run, checkName, clientName,

	ContentType(..), SignatureAlgorithm(..), SecretKey(..),
	HashAlgorithm(..), HandshakeM, Handshake(..), NamedCurve(..),
	Alert(..), AlertLevel(..), AlertDescription(..), Partner(..),
	tlsGet, tlsGetContentType, tlsPut,
	ClientCertificateType(..), SessionId(..), CompressionMethod(..),
	TlsM, TlsHandle(..), finishedHash, flushCipherSuite, DigitallySigned(..),
	handshakeHash, rsaPadding, debugCipherSuite, decryptRsa, randomByteString,
	generateKeys, ClientKeyExchange(..), validate', setClientNames,
	CertificateRequest(..), ClientHello(..), ServerHello(..), withRandom,
	execHandshakeM, setCipherSuite,

	readHandshake,
	readContent,
	Content(..), ChangeCipherSpec(..),
	contentToByteString, contentListToByteString,
) where

import Prelude hiding (read)

import Control.Monad (liftM)
import "monads-tf" Control.Monad.Error (throwError)
import Data.Word (Word8, Word16)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Codec.Bytable as B
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Types.PubKey.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import HandshakeType (
	Handshake(..),
	ClientHello(..), ServerHello(..),
		SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), NamedCurve(..),
	CertificateRequest(..),
		ClientCertificateType(..),
		SignatureAlgorithm(..), HashAlgorithm(..),
	ClientKeyExchange(..),
	DigitallySigned(..) )
import HandshakeMonad (
	TlsM, run,
	HandshakeM, execHandshakeM,
		withRandom, randomByteString, generateKeys, decryptRsa,
	ValidateHandle(..), validate',
	TlsHandle(..),
		checkName, clientName, setClientNames,
		setCipherSuite, flushCipherSuite, debugCipherSuite,
		tlsGetContentType, tlsGet, tlsPut,
	ContentType(..), EcdsaSign(..),
	Alert(..), AlertLevel(..), AlertDescription(..),
	Partner(..), handshakeHash, finishedHash, rsaPadding )

readHandshake :: (HandleLike h, CPRG g) => HandshakeM h g Handshake
readHandshake = do
	cnt <- readContent
	case cnt of
		ContentHandshake hs
			| True -> return hs
			| otherwise -> throwError $ Alert
				AlertLevelFatal
				AlertDescriptionProtocolVersion
				"Not supported layer version"
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage "Not Handshake"

readContent :: (HandleLike h, CPRG g) => HandshakeM h g Content
readContent = parseContent tlsGet =<< tlsGetContentType

parseContent :: Monad m => (Int -> m BS.ByteString) -> ContentType -> m Content
parseContent rd ContentTypeChangeCipherSpec =
	(ContentChangeCipherSpec . either error id . B.fromByteString) `liftM` rd 1
parseContent rd ContentTypeAlert =
	((\[al, ad] -> ContentAlert al ad) . BS.unpack) `liftM` rd 2
parseContent rd ContentTypeHandshake = ContentHandshake `liftM` do
	t <- rd 1
	len <- rd 3
	body <- rd . either error id $ B.fromByteString len
	return . either error id . B.fromByteString $ BS.concat [t, len, body]
parseContent _ ContentTypeApplicationData = undefined
parseContent _ _ = undefined

contentListToByteString :: [Content] -> (ContentType, BS.ByteString)
contentListToByteString cs = let fs@((ct, _) : _) = map contentToByteString cs in
	(ct, BS.concat $ map snd fs)

contentToByteString :: Content -> (ContentType, BS.ByteString)
contentToByteString (ContentChangeCipherSpec ccs) =
	(ContentTypeChangeCipherSpec, B.toByteString ccs)
contentToByteString (ContentAlert al ad) = (ContentTypeAlert, BS.pack [al, ad])
contentToByteString (ContentHandshake hss) =
	(ContentTypeHandshake, B.toByteString hss)

data Content
	= ContentChangeCipherSpec ChangeCipherSpec
	| ContentAlert Word8 Word8
	| ContentHandshake Handshake
	deriving Show

data ChangeCipherSpec
	= ChangeCipherSpec
	| ChangeCipherSpecRaw Word8
	deriving Show

instance B.Bytable ChangeCipherSpec where
	fromByteString bs = case BS.unpack bs of
			[1] -> Right ChangeCipherSpec
			[ccs] -> Right $ ChangeCipherSpecRaw ccs
			_ -> Left "Content.hs: instance Bytable ChangeCipherSpec"
	toByteString ChangeCipherSpec = BS.pack [1]
	toByteString (ChangeCipherSpecRaw ccs) = BS.pack [ccs]

data ServerKeyExchange
	= ServerKeyExchange BS.ByteString BS.ByteString HashAlgorithm SignatureAlgorithm BS.ByteString
	deriving Show

instance B.Bytable ServerKeyExchange where
	fromByteString = undefined
	toByteString = serverKeyExchangeToByteString

serverKeyExchangeToByteString :: ServerKeyExchange -> BS.ByteString
serverKeyExchangeToByteString
	(ServerKeyExchange params dhYs hashA sigA sn) =
	BS.concat [
		params, dhYs, B.toByteString hashA, B.toByteString sigA,
		B.addLength (undefined :: Word16) sn ]

data EcCurveType
	= ExplicitPrime
	| ExplicitChar2
	| NamedCurve
	| EcCurveTypeRaw Word8
	deriving Show

instance B.Bytable EcCurveType where
	fromByteString = undefined
	toByteString ExplicitPrime = BS.pack [1]
	toByteString ExplicitChar2 = BS.pack [2]
	toByteString NamedCurve = BS.pack [3]
	toByteString (EcCurveTypeRaw w) = BS.pack [w]

instance SecretKey RSA.PrivateKey where
	sign sk hs bs = let
		h = hs bs
		a = [ASN1.Start ASN1.Sequence,
			ASN1.Start ASN1.Sequence,
			ASN1.OID [1, 3, 14, 3, 2, 26],
			ASN1.Null,
			ASN1.End ASN1.Sequence,
			ASN1.OctetString h,
			ASN1.End ASN1.Sequence]
		b = ASN1.encodeASN1' ASN1.DER a
		pd = BS.concat [
			"\x00\x01", BS.replicate (125 - BS.length b) 0xff,
			"\NUL", b ] in
		RSA.dp Nothing sk pd
	signatureAlgorithm _ = SignatureAlgorithmRsa

class SecretKey sk where
	sign :: sk -> (BS.ByteString -> BS.ByteString) ->
		BS.ByteString -> BS.ByteString
	signatureAlgorithm :: sk -> SignatureAlgorithm

instance SecretKey ECDSA.PrivateKey where
	sign sk hs bs = let
		Just (ECDSA.Signature r s) = ECDSA.signWith 4649 sk hs bs in
		B.toByteString $ EcdsaSign 0x30 (2, r) (2, s)
	signatureAlgorithm _ = SignatureAlgorithmEcdsa
