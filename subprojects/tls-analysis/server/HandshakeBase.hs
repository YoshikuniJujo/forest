{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports,
	TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module HandshakeBase (
	HM.TlsM, HM.run, HM.HandshakeM, HM.execHandshakeM,
	HM.withRandom, HM.randomByteString,
	HM.TlsHandle, HM.setClientNames, HM.checkName, HM.clientName,
		readHandshake, writeHandshake,
		getChangeCipherSpec, putChangeCipherSpec,
	HM.ValidateHandle(..), HM.validate',
	HM.Alert(..), HM.AlertLevel(..), HM.AlertDescription(..),
	ServerKeyExchange(..), ServerHelloDone(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), HashAlgorithm(..), SignatureAlgorithm(..),
		setCipherSuite,
	CertificateRequest(..),
		ClientCertificateType(..), SecretKey(..),
	ClientKeyExchange(..),
		HM.generateKeys, HM.decryptRsa, HM.rsaPadding, HM.debugCipherSuite,
	DigitallySigned(..), HM.handshakeHash, flushCipherSuite,
	HM.Partner(..), finishedHash,
) where

import Prelude hiding (read)

import Control.Arrow (first)
import Control.Monad (liftM, ap)
import "monads-tf" Control.Monad.State (modify, gets)
import "monads-tf" Control.Monad.Error (throwError)
import Data.HandleLike (HandleLike(..))
import Data.Bits
import Data.Word (Word8)
-- import System.Random
import "crypto-random" Crypto.Random (CPRG, cprgGenerate)

import qualified Data.ByteString as BS
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Codec.Bytable as B
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Types.PubKey.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.Types.PubKey.ECC as ECC

import HandshakeType (
	Handshake(..), HandshakeItem(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..),
	ServerKeyExchange(..),
	CertificateRequest(..),
		ClientCertificateType(..),
		SignatureAlgorithm(..), HashAlgorithm(..),
	ServerHelloDone(..), ClientKeyExchange(..),
	DigitallySigned(..), Finished(..) )
import qualified HandshakeMonad as HM (
	TlsM, run, HandshakeM, execHandshakeM, withRandom, randomByteString,
	ValidateHandle(..), validate',
	TlsHandle(..), ContentType(..),
		checkName, clientName, setClientNames,
		setCipherSuite, flushCipherSuite, debugCipherSuite,
		tlsGetContentType, tlsGet, tlsPut, generateKeys, decryptRsa,
	Alert(..), AlertLevel(..), AlertDescription(..),
	Partner(..), handshakeHash, finishedHash, rsaPadding )
import Rfc6979 (generateK)
import Ecdsa (blindSign)

readHandshake :: (HandleLike h, CPRG g, HandshakeItem hi) => HM.HandshakeM h g hi
readHandshake = do
	cnt <- readContent HM.tlsGet =<< HM.tlsGetContentType
	hs <- case cnt of
		ContentHandshake hs -> return hs
		_ -> throwError $ HM.Alert
			HM.AlertLevelFatal HM.AlertDescriptionUnexpectedMessage
			"HandshakeBase.readHandshake: not handshake"
	case fromHandshake hs of
		Just i -> return i
		_ -> throwError . HM.Alert
			HM.AlertLevelFatal HM.AlertDescriptionUnexpectedMessage $
			"HandshakeBase.readHandshake: type mismatch " ++ show hs

getChangeCipherSpec :: (HandleLike h, CPRG g) => HM.HandshakeM h g ()
getChangeCipherSpec = do
	cnt <- readContent HM.tlsGet =<< HM.tlsGetContentType
	case cnt of
		ContentChangeCipherSpec ChangeCipherSpec -> return ()
		_ -> throwError $ HM.Alert
			HM.AlertLevelFatal HM.AlertDescriptionUnexpectedMessage
			"HandshakeBase.getChangeCipherSpec: not change cipher spec"

readContent :: Monad m => (Int -> m BS.ByteString) -> HM.ContentType -> m Content
readContent rd HM.ContentTypeChangeCipherSpec =
	(ContentChangeCipherSpec . either error id . B.fromByteString) `liftM` rd 1
readContent rd HM.ContentTypeAlert =
	((\[al, ad] -> ContentAlert al ad) . BS.unpack) `liftM` rd 2
readContent rd HM.ContentTypeHandshake = ContentHandshake `liftM` do
	(t, len) <- (,) `liftM` rd 1 `ap` rd 3
	body <- rd . either error id $ B.fromByteString len
	return . either error id . B.fromByteString $ BS.concat [t, len, body]
readContent _ _ = undefined

writeHandshake ::
	(HandleLike h, CPRG g, HandshakeItem hi) => hi -> HM.HandshakeM h g ()
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
encodeContent (ContentAlert al ad) =
	(HM.ContentTypeAlert, BS.pack [al, ad])
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
	type Blinder sk
	generateBlinder :: CPRG g => sk -> g -> (Blinder sk, g)
	sign :: Blinder sk -> sk -> (BS.ByteString -> BS.ByteString, Int) ->
		BS.ByteString -> BS.ByteString
	signatureAlgorithm :: sk -> SignatureAlgorithm

instance SecretKey RSA.PrivateKey where
	type Blinder RSA.PrivateKey = RSA.Blinder
	generateBlinder sk rng =
		RSA.generateBlinder rng . RSA.public_n $ RSA.private_pub sk
	sign bl sk hs bs = let
		h = fst hs bs
		a = [ASN1.Start ASN1.Sequence,
				ASN1.Start ASN1.Sequence,
					ASN1.OID [1, 3, 14, 3, 2, 26],
					ASN1.Null, ASN1.End ASN1.Sequence,
				ASN1.OctetString h, ASN1.End ASN1.Sequence]
		b = ASN1.encodeASN1' ASN1.DER a
		pd = BS.concat [ "\x00\x01",
			BS.replicate (125 - BS.length b) 0xff, "\NUL", b ] in
		RSA.dp (Just bl) sk pd
	signatureAlgorithm _ = SignatureAlgorithmRsa

randomR :: CPRG g => (Integer, Integer) -> g -> (Integer, g)
randomR (mn, mx) g
	| mn <= n && n <= mx = (n, g')
	| otherwise = randomR (mn, mx) g'
	where
	(bs, g') = cprgGenerate (rlen mx `div` 8) g
	Right n = B.fromByteString bs
	

qlen, rlen :: Integer -> Int
qlen 0 = 0
qlen n = 1 + qlen (n `shiftR` 1)
rlen 0 = 0
rlen q = 8 + rlen (q `shiftR` 8)

instance SecretKey ECDSA.PrivateKey where
	type Blinder ECDSA.PrivateKey = Integer
	generateBlinder (ECDSA.PrivateKey c _) =
		randomR (1, ECC.ecc_n $ ECC.common_curve c)
	sign bl sk hs bs = let
		Just (ECDSA.Signature r s) =
			blindSign bl (generateK hs q x bs) sk (fst hs) bs in
--			ECDSA.signWith (generateK hs q x bs) sk (fst hs) bs in
		B.toByteString $ ECDSA.Signature r s
		where
		q = ECC.ecc_n . ECC.common_curve $ ECDSA.private_curve sk
		x = ECDSA.private_d sk
	signatureAlgorithm _ = SignatureAlgorithmEcdsa

setCipherSuite :: HandleLike h => CipherSuite -> HM.HandshakeM h g ()
setCipherSuite = modify . first . HM.setCipherSuite

flushCipherSuite :: (HandleLike h, CPRG g) => HM.Partner -> HM.HandshakeM h g ()
flushCipherSuite p =
	HM.flushCipherSuite p `liftM` gets fst >>= modify . first . const

finishedHash :: (HandleLike h, CPRG g) => HM.Partner -> HM.HandshakeM h g Finished
finishedHash = (Finished `liftM`) . HM.finishedHash
