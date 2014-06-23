{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports,
	TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module HandshakeMonad (
	ValidateHandle(..),
	TH.run, setClientNames, checkName, clientName,

	TH.TlsHandle(..),
	TH.ContentType(..),
	TH.Alert(..), TH.AlertLevel(..), TH.AlertDescription(..),
	TH.Partner(..),
	TH.cipherSuite,
	flushCipherSuite,
	TH.TlsM,
	TH.newHandle, setCipherSuite,

	handshakeHash, withRandom, tlsGet, tlsGetContentType, tlsPut,
	HandshakeM, randomByteString,
	handshakeValidate, generateKeys, debugCipherSuite, finishedHash,

	rsaPadding,
	decryptRsa,
	execHandshakeM,
) where

import Prelude hiding (read)

import Control.Arrow
import Control.Monad (liftM)
import "monads-tf" Control.Monad.Trans (lift)
import "monads-tf" Control.Monad.State (StateT, execStateT, get, gets, put, modify)
import "monads-tf" Control.Monad.Error (throwError)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.Maybe (listToMaybe)
import Data.Word (Word8)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable as B
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.HashDescr as RSA
import qualified Crypto.Types.PubKey.ECDSA as ECDSA

import qualified TlsHandle as TH (
	TlsM, Alert(..), AlertLevel(..), AlertDescription(..),
		run, withRandom, randomByteString,
	TlsHandle(..), Keys, ContentType(..),
		newHandle, tlsGetContentType, tlsGet, tlsPut, generateKeys,
		cipherSuite, setCipherSuite, flushCipherSuite, debugCipherSuite,
	Partner(..), finishedHash, handshakeHash, CipherSuite(..) )

import qualified Crypto.Hash.SHA256 as SHA256

type HandshakeM h g = StateT (TH.TlsHandle h g, SHA256.Ctx) (TH.TlsM h g)

generateKeys :: HandleLike h =>
	(BS.ByteString, BS.ByteString) -> BS.ByteString -> HandshakeM h g ()
generateKeys (cr, sr) pms = do
	ks <- generateKeys_ cr sr pms
	th <- gets fst
	modify . first $ const th { TH.keys = ks }

setClientNames :: HandleLike h => [String] -> HandshakeM h g ()
setClientNames nms = do
	th <- gets fst
	modify . first $ const th { TH.clientNames = nms }

execHandshakeM :: HandleLike h =>
	h -> HandshakeM h g () -> TH.TlsM h g (TH.TlsHandle h g)
execHandshakeM h = liftM fst . (newState h >>=) . execStateT

newState :: HandleLike h => h -> TH.TlsM h g (TH.TlsHandle h g, SHA256.Ctx)
newState h = (, SHA256.init) `liftM` TH.newHandle h

tlsPut :: (HandleLike h, CPRG g) =>
	TH.ContentType -> BS.ByteString -> HandshakeM h g ()
tlsPut ct bs = get >>= lift . (\t -> TH.tlsPut t ct bs) >>= put

handshakeValidate :: ValidateHandle h =>
	X509.CertificateStore -> X509.CertificateChain ->
	HandshakeM h g [X509.FailedReason]
handshakeValidate cs cc = gets fst >>= \t ->
	lift . lift . lift $ validate (TH.tlsHandle t) cs cc

generateKeys_ :: HandleLike h => BS.ByteString -> BS.ByteString -> BS.ByteString ->
	HandshakeM h g TH.Keys
generateKeys_ cr sr pms = do
	th <- gets fst
	lift $ TH.generateKeys (TH.cipherSuite th) cr sr pms

randomByteString :: (HandleLike h, CPRG g) => Int -> HandshakeM h g BS.ByteString
randomByteString = lift . TH.randomByteString

decryptRsa :: (HandleLike h, CPRG g) =>
	RSA.PrivateKey -> BS.ByteString -> HandshakeM h g BS.ByteString
decryptRsa sk e =
	either (throwError . strMsg . show) return =<<
	withRandom (\g -> RSA.decryptSafer g sk e)

debugCipherSuite :: HandleLike h => String -> HandshakeM h g ()
debugCipherSuite msg = do
	th <- gets fst
	lift $ TH.debugCipherSuite th msg

rsaPadding :: RSA.PublicKey -> BS.ByteString -> BS.ByteString
rsaPadding pub bs =
	case RSA.padSignature (RSA.public_size pub) $
			RSA.digestToASN1 RSA.hashDescrSHA256 bs of
		Right pd -> pd
		Left msg -> error $ show msg

finishedHash :: (HandleLike h, CPRG g) => TH.Partner -> HandshakeM h g BS.ByteString
finishedHash p = get >>= lift . flip TH.finishedHash p

class HandleLike h => ValidateHandle h where
	validate :: h -> X509.CertificateStore -> X509.CertificateChain ->
		HandleMonad h [X509.FailedReason]

instance ValidateHandle Handle where
	validate _ cs = X509.validate X509.HashSHA256 X509.defaultHooks
		validationChecks cs validationCache ("", "")
		where
		validationCache = X509.ValidationCache
			(\_ _ _ -> return X509.ValidationCacheUnknown)
			(\_ _ _ -> return ())
		validationChecks = X509.defaultChecks { X509.checkFQHN = False }

tlsGet :: (HandleLike h, CPRG g) => Int -> HandshakeM h g BS.ByteString
tlsGet n = do -- (snd `liftM`) . (get >>=) . (.) lift . flip TH.tlsGet
	t <- get
	((_, bs), t') <- lift $ TH.tlsGet t n
	put t'
	return bs

tlsGetContentType :: (HandleLike h, CPRG g) => HandshakeM h g TH.ContentType
tlsGetContentType = gets fst >>= lift . TH.tlsGetContentType

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

instance B.Bytable ECDSA.Signature where
	fromByteString = decodeSignature
	toByteString = encodeSignature

decodeSignature :: BS.ByteString -> Either String ECDSA.Signature
decodeSignature bs = case ASN1.decodeASN1' ASN1.DER bs of
	Right [ASN1.Start ASN1.Sequence,
		ASN1.IntVal r,
		ASN1.IntVal s,
		ASN1.End ASN1.Sequence] ->
		Right $ ECDSA.Signature r s
	Right _ -> Left "KeyExchange.decodeSignature"
	Left err -> Left $ "KeyExchange.decodeSignature: " ++ show err

encodeSignature :: ECDSA.Signature -> BS.ByteString
encodeSignature (ECDSA.Signature r s) = ASN1.encodeASN1' ASN1.DER [
	ASN1.Start ASN1.Sequence,
	ASN1.IntVal r, ASN1.IntVal s, ASN1.End ASN1.Sequence ]

handshakeHash :: HandleLike h => HandshakeM h g BS.ByteString
handshakeHash = get >>= lift . TH.handshakeHash

withRandom :: HandleLike h => (g -> (a, g)) -> HandshakeM h g a
withRandom = lift . TH.withRandom

checkName :: TH.TlsHandle h g -> String -> Bool
checkName tc n = n `elem` TH.clientNames tc

clientName :: TH.TlsHandle h g -> Maybe String
clientName = listToMaybe . TH.clientNames

setCipherSuite :: HandleLike h => TH.CipherSuite -> HandshakeM h g ()
setCipherSuite = modify . first . TH.setCipherSuite

flushCipherSuite :: (HandleLike h, CPRG g) => TH.Partner -> HandshakeM h g ()
flushCipherSuite p =
	TH.flushCipherSuite p `liftM` gets fst >>= modify . first . const
