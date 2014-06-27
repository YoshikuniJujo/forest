{-# LANGUAGE TypeFamilies #-}

module ClSecretKey (ClSecretKey(..)) where

import Data.Maybe

import qualified Data.X509 as X509
import qualified Data.ByteString as BS
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding

import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.PubKey.RSA as RSA

import HandshakeBase

class ClSecretKey sk where
	type SecPubKey sk
	getPubKey :: sk -> X509.PubKey -> SecPubKey sk
	clSign :: sk -> SecPubKey sk -> BS.ByteString -> BS.ByteString
	clAlgorithm :: sk -> (HashAlgorithm, SignatureAlgorithm)

instance ClSecretKey ECDSA.PrivateKey where
	type SecPubKey ECDSA.PrivateKey = ()
	getPubKey _ _ = ()
	clSign sk _ = encodeSignature . fromJust . ECDSA.signWith 4649 sk id
	clAlgorithm _ = (Sha256, Ecdsa)

encodeSignature :: ECDSA.Signature -> BS.ByteString
encodeSignature (ECDSA.Signature r s) =
	encodeASN1' DER [Start Sequence, IntVal r, IntVal s, End Sequence]

instance ClSecretKey RSA.PrivateKey where
	type SecPubKey RSA.PrivateKey = RSA.PublicKey
	getPubKey _ (X509.PubKeyRSA pk) = pk
	getPubKey _ _ = error "bad"
	clSign sk pk m = let pd = rsaPadding pk m in RSA.dp Nothing sk pd
	clAlgorithm _ = (Sha256, Rsa)
