{-# LANGUAGE PackageImports, OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsIo (
	TlsIo, evalTlsIo, liftIO, throwError,
	Partner(..), opponent,
	readCached, readLen, writeLen, 

	ContentType(..), readContentType, writeContentType,
	Version, readVersion, writeVersion,
	CipherSuite(..), getCipherSuite,

	setVersion, setClientRandom, setServerRandom,
	cacheCipherSuite, flushCipherSuite, generateMasterSecret,

	encryptRSA, decrypt, encrypt, takeBodyMac, calcMac,
	updateHash, updateSequenceNumber, updateSequenceNumberSmart,
	finishedHash,

	randomByteString, clientVerifySign,
) where

import Prelude hiding (read)

import System.IO
import Control.Applicative
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.State
import Data.Word
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random
import Crypto.Cipher.AES
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.HashDescr as RSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

import qualified MasterSecret as MS
import Basic

type TlsIo cnt = ErrorT String (StateT (TlsClientState cnt) IO)

data TlsClientState cnt = TlsClientState {
	tlssHandle			:: Handle,
	tlssContentCache		:: [cnt],

	tlssVersion			:: Maybe MS.MSVersion,
	tlssClientWriteCipherSuite	:: CipherSuite,
	tlssServerWriteCipherSuite	:: CipherSuite,
	tlssCachedCipherSuite		:: CipherSuite,

	tlssMasterSecret		:: Maybe BS.ByteString,
	tlssClientRandom		:: Maybe BS.ByteString,
	tlssServerRandom		:: Maybe BS.ByteString,
	tlssClientWriteMacKey		:: Maybe BS.ByteString,
	tlssServerWriteMacKey		:: Maybe BS.ByteString,
	tlssClientWriteKey		:: Maybe BS.ByteString,
	tlssServerWriteKey		:: Maybe BS.ByteString,

	tlssRandomGen			:: SystemRNG,
	tlssSha256Ctx			:: SHA256.Ctx,
	tlssClientSequenceNumber	:: Word64,
	tlssServerSequenceNumber	:: Word64
 }

initTlsClientState :: EntropyPool -> Handle -> TlsClientState cnt
initTlsClientState ep sv = TlsClientState {
	tlssHandle			= sv,
	tlssContentCache		= [],

	tlssVersion			= Nothing,
	tlssClientWriteCipherSuite	= TLS_NULL_WITH_NULL_NULL,
	tlssServerWriteCipherSuite	= TLS_NULL_WITH_NULL_NULL,
	tlssCachedCipherSuite		= TLS_NULL_WITH_NULL_NULL,

	tlssMasterSecret		= Nothing,
	tlssClientRandom		= Nothing,
	tlssServerRandom		= Nothing,
	tlssClientWriteMacKey		= Nothing,
	tlssServerWriteMacKey		= Nothing,
	tlssClientWriteKey		= Nothing,
	tlssServerWriteKey		= Nothing,

	tlssRandomGen			= cprgCreate ep,
	tlssSha256Ctx			= SHA256.init,
	tlssClientSequenceNumber	= 0,
	tlssServerSequenceNumber	= 0
 }

data Partner = Server | Client deriving (Show, Eq)

opponent :: Partner -> Partner
opponent Server = Client
opponent Client = Server

readCached :: TlsIo cnt [cnt] -> TlsIo cnt cnt
readCached rd = do
	cch <- gets tlssContentCache
	tlss <- get
	case cch of
		[] -> do
			r : cch' <- rd
			put tlss { tlssContentCache = cch' }
			return r
		r : cch' -> do
			put tlss { tlssContentCache = cch' }
			return r

setVersion :: MS.Version -> TlsIo cnt ()
setVersion v = do
	tlss <- get
	case MS.versionToVersion v of
		Just v' -> put tlss { tlssVersion = Just v' }
		_ -> throwError "setVersion: Not implemented"

{-
handle :: Partner -> TlsClientState cnt -> Handle
handle Server = tlssHandle
handle _ = error "No Client Handle"
-}

evalTlsIo :: TlsIo cnt a -> EntropyPool -> Handle -> IO a
evalTlsIo io ep sv = do
	ret <- runErrorT io `evalStateT` initTlsClientState ep sv
	case ret of
		Right r -> return r
		Left err -> error err

read :: Int -> TlsIo cnt BS.ByteString
read n = do
	h <- gets tlssHandle
	r <- liftIO $ BS.hGet h n
	if BS.length r == n
		then return r
		else throwError $ "Basic.read: bad reading: " ++
			show (BS.length r) ++ " " ++ show n

write :: BS.ByteString -> TlsIo cnt ()
write dat = do
	h <- gets tlssHandle
	liftIO $ BS.hPut h dat

readLen :: Int -> TlsIo cnt BS.ByteString
readLen n = do
	len <- read n
	read $ byteStringToInt len

writeLen :: Int -> BS.ByteString -> TlsIo cnt ()
writeLen n bs = do
	write . intToByteString n $ BS.length bs
	write bs

encryptRSA :: RSA.PublicKey -> BS.ByteString -> TlsIo cnt BS.ByteString
encryptRSA pub pln = do
	g <- gets tlssRandomGen
	tlss <- get
	let (Right e, g') = RSA.encrypt g pub pln
	put tlss { tlssRandomGen = g' }
	return e

setClientRandom, setServerRandom :: Random -> TlsIo cnt ()
setClientRandom (Random cr) = do
	tlss <- get
	put $ tlss { tlssClientRandom = Just cr }
setServerRandom (Random sr) = do
	tlss <- get
	put $ tlss { tlssServerRandom = Just sr }

cacheCipherSuite :: CipherSuite -> TlsIo cnt ()
cacheCipherSuite cs = do
	tlss <- get
	put $ tlss { tlssCachedCipherSuite = cs }

flushCipherSuite :: Partner -> TlsIo cnt ()
flushCipherSuite p = do
	tlss <- get
	case p of
		Client -> put tlss {
			tlssClientWriteCipherSuite = tlssCachedCipherSuite tlss }
		Server -> put tlss {
			tlssServerWriteCipherSuite = tlssCachedCipherSuite tlss }

generateMasterSecret :: BS.ByteString -> TlsIo cnt ()
generateMasterSecret pms = do
	mv <- gets tlssVersion
	mcr <- gets $ (MS.ClientRandom <$>) . tlssClientRandom
	msr <- gets $ (MS.ServerRandom <$>) . tlssServerRandom
	case (mv, mcr, msr) of
		(Just v, Just cr, Just sr) -> do
			let	ms = MS.generateMasterSecret v pms cr sr
				ems = MS.generateKeyBlock v cr sr ms 104
				[cwmk, swmk, cwk, swk] =
					divide [ 20, 20, 16, 16 ] ems
			tlss <- get
			put $ tlss {
				tlssMasterSecret = Just ms,
				tlssClientWriteMacKey = Just cwmk,
				tlssServerWriteMacKey = Just swmk,
				tlssClientWriteKey = Just cwk,
				tlssServerWriteKey = Just swk
			 }
		_ -> throwError "No client random / No server random"

divide :: [Int] -> BS.ByteString -> [BS.ByteString]
divide [] _ = []
divide (n : ns) bs
	| bs == BS.empty = []
	| otherwise = let (x, xs) = BS.splitAt n bs in x : divide ns xs

decrypt :: Partner -> BS.ByteString -> TlsIo cnt BS.ByteString
decrypt partner e = do
	version <- gets tlssVersion
	set <- getCipherSet partner
	case (version, set) of
		(Just MS.TLS12, (TLS_RSA_WITH_AES_128_CBC_SHA, Just key)) -> do
			let d = decryptCBC (initAES key)
				(BS.take 16 e) (BS.drop 16 e)
			return d
		(_, (TLS_NULL_WITH_NULL_NULL, _)) -> return e
		_ -> throwError "clientWriteDecrypt: No keys or Bad cipher suite"

encrypt :: Partner -> BS.ByteString -> TlsIo cnt BS.ByteString
encrypt partner d = do
	version <- gets tlssVersion
	set <- getCipherSet partner
	case (version, set) of
		(Just MS.TLS12, (TLS_RSA_WITH_AES_128_CBC_SHA, Just key)) -> do
			iv <- randomByteString 16
			let	e = encryptCBC (initAES key) iv d
			return $ iv `BS.append` e
		(_, (TLS_NULL_WITH_NULL_NULL, _)) -> return d
		_ -> throwError "clientWriteDecrypt: No keys or Bad cipher suite"

getCipherSet :: Partner -> TlsIo cnt (CipherSuite, Maybe BS.ByteString)
getCipherSet partner = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	mkey <- gets $ case partner of
		Client -> tlssClientWriteKey
		Server -> tlssServerWriteKey
	return (cs, mkey)

takeBodyMac :: Partner -> BS.ByteString -> TlsIo cnt (BS.ByteString, BS.ByteString)
takeBodyMac partner bmp = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	case cs of
		TLS_RSA_WITH_AES_128_CBC_SHA -> return $ bodyMac bmp
		TLS_NULL_WITH_NULL_NULL -> return (bmp, "")
		_ -> throwError "takeBodyMac: Bad cipher suite"

bodyMac :: BS.ByteString -> (BS.ByteString, BS.ByteString)
bodyMac bs = let
	(bm, _) = BS.splitAt (BS.length bs - fromIntegral (BS.last bs) - 1) bs in
	BS.splitAt (BS.length bm - 20) bm

updateHash :: BS.ByteString -> TlsIo cnt ()
updateHash bs = do
	sha256 <- gets tlssSha256Ctx
	tlss <- get
	put tlss { tlssSha256Ctx = SHA256.update sha256 bs }

finishedHash :: Partner -> TlsIo cnt BS.ByteString
finishedHash partner = do
	mms <- gets tlssMasterSecret
	sha256 <- SHA256.finalize <$> gets tlssSha256Ctx
	version <- do
		mv <- gets tlssVersion
		case mv of
			Just v -> return v
			_ -> throwError "finishedHash: no version"
	case (version, mms) of
		(MS.TLS12, Just ms) -> return $
			MS.generateFinished version (partner == Client) ms sha256
		_ -> throwError "No master secrets"

getSequenceNumber :: Partner -> TlsIo cnt Word64
getSequenceNumber partner = gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber

updateSequenceNumber :: Partner -> TlsIo cnt Word64
updateSequenceNumber partner = do
	sn <- gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber
	tlss <- get
	put $ case partner of
		Client -> tlss { tlssClientSequenceNumber = succ sn }
		Server -> tlss { tlssServerSequenceNumber = succ sn }
	return sn

updateSequenceNumberSmart :: Partner -> TlsIo cnt ()
updateSequenceNumberSmart partner = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	case cs of
		TLS_RSA_WITH_AES_128_CBC_SHA ->
			void $ updateSequenceNumber partner
		TLS_NULL_WITH_NULL_NULL -> return ()
		_ -> throwError "not implemented"

calcMac :: Partner -> ContentType -> Version -> BS.ByteString -> TlsIo cnt BS.ByteString
calcMac partner ct v body = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	calcMacCs cs partner ct v body

calcMacCs :: CipherSuite -> Partner -> ContentType -> Version -> BS.ByteString ->
	TlsIo cnt BS.ByteString
calcMacCs TLS_RSA_WITH_AES_128_CBC_SHA partner ct v body = do
	sn <- getSequenceNumber partner
	let hashInput = BS.concat [
		word64ToByteString sn ,
		contentTypeToByteString ct,
		versionToByteString v,
		lenBodyToByteString 2 body ]
	Just macKey <- case partner of
		Client -> gets tlssClientWriteMacKey
		Server -> gets tlssServerWriteMacKey
	mv <- gets tlssVersion
	case mv of
		Just MS.TLS12 -> return $ MS.hmac SHA1.hash 64 macKey hashInput
		_ -> throwError "calcMacCs: not supported version"
calcMacCs TLS_NULL_WITH_NULL_NULL _ _ _ _ = return ""
calcMacCs _ _ _ _ _ = throwError "calcMac: not supported"

readVersion :: TlsIo cnt Version
readVersion = byteStringToVersion <$> read 2

writeVersion :: Version -> TlsIo cnt ()
writeVersion v = write $ versionToByteString v

readContentType :: TlsIo cnt ContentType
readContentType = byteStringToContentType <$> read 1

writeContentType :: ContentType -> TlsIo cnt ()
writeContentType ct = write $ contentTypeToByteString ct

getCipherSuite :: Partner -> TlsIo cnt CipherSuite
getCipherSuite partner = gets $ case partner of
	Client -> tlssClientWriteCipherSuite
	Server -> tlssServerWriteCipherSuite

randomByteString :: Int -> TlsIo cnt BS.ByteString
randomByteString len = do
	gen <- gets tlssRandomGen
	let (r, gen') = cprgGenerate len gen
	tlss <- get
	put tlss { tlssRandomGen = gen' }
	return r

clientVerifySign :: RSA.PrivateKey -> TlsIo cnt BS.ByteString
clientVerifySign pkys = do
	sha256 <- gets $ SHA256.finalize . tlssSha256Ctx
	let	pubys = RSA.private_pub pkys
		Right hashed = RSA.padSignature (RSA.public_size pubys) $
			RSA.digestToASN1 RSA.hashDescrSHA256 sha256
		signed = RSA.dp Nothing pkys hashed
	return signed
