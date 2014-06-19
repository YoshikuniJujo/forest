{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports,
	TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module HandshakeBase (
	HM.TlsM, HM.run, HM.HandshakeM, HM.execHandshakeM,
	HM.withRandom, HM.randomByteString,
	HM.TlsHandle, HM.setClientNames, HM.checkName, HM.clientName,
	HM.ValidateHandle(..), HM.validate',
	HM.Alert(..), HM.AlertLevel(..), HM.AlertDescription(..),
	ServerKeyExchange(..), ServerHelloDone(..),
		readHandshake, writeHandshake,
		getChangeCipherSpec, putChangeCipherSpec,
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), HashAlgorithm(..), SignatureAlgorithm(..),
		setCipherSuite,
	CertificateRequest(..),
		ClientCertificateType(..), SecretKey(..), NamedCurve(..),
	ClientKeyExchange(..),
		HM.generateKeys, HM.decryptRsa, HM.rsaPadding, HM.debugCipherSuite,
	DigitallySigned(..), HM.handshakeHash, flushCipherSuite,
	HM.Partner(..), finishedHash,
) where

import Prelude hiding (read)

import Control.Arrow (first)
import Control.Monad (liftM)
import "monads-tf" Control.Monad.State (modify, gets)
import "monads-tf" Control.Monad.Error (throwError)
import Data.HandleLike (HandleLike(..))
import Data.Word (Word8)
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
	Handshake(..), HandshakeItem(..),
		ServerKeyExchange(..), ServerHelloDone(..), Finished(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), NamedCurve(..),
	CertificateRequest(..),
		ClientCertificateType(..),
		SignatureAlgorithm(..), HashAlgorithm(..),
	ClientKeyExchange(..), DigitallySigned(..) )
import qualified HandshakeMonad as HM (
	TlsM, run, HandshakeM, execHandshakeM, withRandom, randomByteString,
	ValidateHandle(..), validate',
	TlsHandle(..), ContentType(..),
		checkName, clientName, setClientNames,
		setCipherSuite, flushCipherSuite, debugCipherSuite,
		tlsGetContentType, tlsGet, tlsPut, generateKeys, decryptRsa,
	Alert(..), AlertLevel(..), AlertDescription(..),
	EcdsaSign(..), Partner(..), handshakeHash, finishedHash, rsaPadding )

readHandshake :: (HandleLike h, CPRG g, HandshakeItem hi) => HM.HandshakeM h g hi
readHandshake = do
	cnt <- parseContent HM.tlsGet =<< HM.tlsGetContentType
	hs <- case cnt of
		ContentHandshake hs -> return hs
		_ -> throwError $ HM.Alert
			HM.AlertLevelFatal HM.AlertDescriptionUnexpectedMessage
			"HandshakeBase.readHandshake: not handshake"
	case fromHandshake hs of
		Just i -> return i
		_ -> throwError . HM.Alert
			HM.AlertLevelFatal HM.AlertDescriptionUnexpectedMessage $
			"HandshakeBase.readHandshake: " ++ show hs

getChangeCipherSpec :: (HandleLike h, CPRG g) => HM.HandshakeM h g ()
getChangeCipherSpec = do
	cnt <- parseContent HM.tlsGet =<< HM.tlsGetContentType
	case cnt of
		ContentChangeCipherSpec ChangeCipherSpec -> return ()
		_ -> throwError $ HM.Alert
			HM.AlertLevelFatal HM.AlertDescriptionUnexpectedMessage
			"HandshakeBase.getChangeCipherSpec: not change cipher spec"

parseContent :: Monad m => (Int -> m BS.ByteString) -> HM.ContentType -> m Content
parseContent rd HM.ContentTypeChangeCipherSpec =
	(ContentChangeCipherSpec . either error id . B.fromByteString) `liftM` rd 1
parseContent rd HM.ContentTypeAlert =
	((\[al, ad] -> ContentAlert al ad) . BS.unpack) `liftM` rd 2
parseContent rd HM.ContentTypeHandshake = ContentHandshake `liftM` do
	t <- rd 1
	len <- rd 3
	body <- rd . either error id $ B.fromByteString len
	return . either error id . B.fromByteString $ BS.concat [t, len, body]
parseContent _ HM.ContentTypeApplicationData = undefined
parseContent _ _ = undefined

writeHandshake :: (HandleLike h, CPRG g, HandshakeItem hi) =>
	hi -> HM.HandshakeM h g ()
writeHandshake = uncurry HM.tlsPut . encodeContent . ContentHandshake . toHandshake

putChangeCipherSpec :: (HandleLike h, CPRG g) => HM.HandshakeM h g ()
putChangeCipherSpec =
	uncurry HM.tlsPut . encodeContent $ ContentChangeCipherSpec ChangeCipherSpec

data Content
	= ContentChangeCipherSpec ChangeCipherSpec
	| ContentAlert Word8 Word8
	| ContentHandshake Handshake
	deriving Show

encodeContent :: Content -> (HM.ContentType, BS.ByteString)
encodeContent (ContentChangeCipherSpec ccs) =
	(HM.ContentTypeChangeCipherSpec, B.toByteString ccs)
encodeContent (ContentAlert al ad) = (HM.ContentTypeAlert, BS.pack [al, ad])
encodeContent (ContentHandshake hss) =
	(HM.ContentTypeHandshake, B.toByteString hss)

data ChangeCipherSpec = ChangeCipherSpec | ChangeCipherSpecRaw Word8 deriving Show

instance B.Bytable ChangeCipherSpec where
	fromByteString bs = case BS.unpack bs of
		[1] -> Right ChangeCipherSpec
		[ccs] -> Right $ ChangeCipherSpecRaw ccs
		_ -> Left "HandshakeBase: ChangeCipherSpec.fromByteString"
	toByteString ChangeCipherSpec = BS.pack [1]
	toByteString (ChangeCipherSpecRaw ccs) = BS.pack [ccs]

class SecretKey sk where
	sign :: sk -> (BS.ByteString -> BS.ByteString) ->
		BS.ByteString -> BS.ByteString
	signatureAlgorithm :: sk -> SignatureAlgorithm

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

instance SecretKey ECDSA.PrivateKey where
	sign sk hs bs = let
		Just (ECDSA.Signature r s) = ECDSA.signWith 4649 sk hs bs in
		B.toByteString $ HM.EcdsaSign 0x30 (2, r) (2, s)
	signatureAlgorithm _ = SignatureAlgorithmEcdsa

setCipherSuite :: HandleLike h => CipherSuite -> HM.HandshakeM h g ()
setCipherSuite = modify . first . HM.setCipherSuite

flushCipherSuite :: (HandleLike h, CPRG g) => HM.Partner -> HM.HandshakeM h g ()
flushCipherSuite p =
	HM.flushCipherSuite p `liftM` gets fst >>= modify . first . const

finishedHash :: (HandleLike h, CPRG g) => HM.Partner -> HM.HandshakeM h g Finished
finishedHash = (Finished `liftM`) . HM.finishedHash
