{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, PackageImports #-}

module TlsHandle (
	TlsM, Alert(..), AlertLevel(..), AlertDescription(..),
		run, withRandom, randomByteString,
	TlsHandle(..), ContentType(..), CipherSuite(..),
		newHandle, getContentType, tlsGet, tlsPut, generateKeys,
		cipherSuite, setCipherSuite, flushCipherSuite, debugCipherSuite,
	Partner(..), handshakeHash, finishedHash ) where

import Prelude hiding (read)

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (second)
import Control.Monad (liftM, when, unless)
import "monads-tf" Control.Monad.State (get, put, lift)
import "monads-tf" Control.Monad.Error (throwError)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.Word (Word8, Word16, Word64)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Codec.Bytable as B
import qualified Crypto.Hash.SHA256 as SHA256

import TlsMonad (
	TlsM, run, thlGet, thlPut, thlClose, thlDebug, thlError,
		withRandom, randomByteString, getBuf, setBuf, getWBuf, setWBuf,
		getClientSn, getServerSn, succClientSn, succServerSn,
	Alert(..), AlertLevel(..), AlertDescription(..), strToAlert,
	ContentType(..), CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	ClientId, newClientId, Keys(..), nullKeys )
import CryptoTools (
	makeKeys, decryptMessage, encryptMessage, hashSha1, hashSha256,
	finishedHash_ )

data TlsHandle h g = TlsHandle {
	clientId :: ClientId,
	tlsHandle :: h, keys :: Keys, clientNames :: [String] }

type HandleHash h g = (TlsHandle h g, SHA256.Ctx)

newHandle :: HandleLike h => h -> TlsM h g (TlsHandle h g)
newHandle h = do
	s <- get
	let (i, s') = newClientId s
	put s'
	return TlsHandle {
		clientId = i, tlsHandle = h, keys = nullKeys, clientNames = [] }

getContentType :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g ContentType
getContentType t = do
	ct <- fst `liftM` getBuf (clientId t)
	(\gt -> case ct of CTNull -> gt; _ -> return ct) $ do
		(ct', bf) <- getWholeWithCt t
		setBuf (clientId t) (ct', bf)
		return ct'

tlsGet :: (HandleLike h, CPRG g) => HandleHash h g ->
	Int -> TlsM h g ((ContentType, BS.ByteString), HandleHash h g)
tlsGet hh@(t, _) n = do
	r@(ct, bs) <- buffered t n
	(r ,) `liftM` case ct of
		ContentTypeHandshake -> updateHash hh bs
		_ -> return hh

buffered :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> Int -> TlsM h g (ContentType, BS.ByteString)
buffered t n = do
	(ct, b) <- getBuf $ clientId t; let rl = n - BS.length b
	if rl <= 0
	then do	let (ret, b') = BS.splitAt n b
		setBuf (clientId t) $ if BS.null b' then (CTNull, "") else (ct, b')
		return (ct, ret)
	else do	(ct', b') <- getWholeWithCt t
		unless (ct' == ct) . throwError . strToAlert $
			"Content Type confliction\n" ++
				"\tExpected: " ++ show ct ++ "\n" ++
				"\tActual  : " ++ show ct' ++ "\n" ++
				"\tData    : " ++ show b'
		when (BS.null b') $ throwError "buffered: No data available"
		setBuf (clientId t) (ct', b')
		second (b `BS.append`) `liftM` buffered t rl

getWholeWithCt :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> TlsM h g (ContentType, BS.ByteString)
getWholeWithCt th = do
	ct <- (either error id . B.decode) `liftM` read th 1
	[_vmjr, _vmnr] <- BS.unpack `liftM` read th 2
	ebody <- read th . either error id . B.decode =<< read th 2
	when (BS.null ebody) $ throwError "getWholeWithCt: ebody is null"
	body <- tlsDecryptMessage th (keys th) ct ebody
	return (ct, body)

tlsPut :: (HandleLike h, CPRG g) =>
	HandleHash h g -> ContentType -> BS.ByteString -> TlsM h g (HandleHash h g)
tlsPut (th, ctx) ct bs = do
	(bct, bbs) <- getWBuf $ clientId th
	case ct of
		ContentTypeChangeCipherSpec -> do
				tlsFlush th
				setWBuf (clientId th) (ct, bs)
				tlsFlush th
				return ()
		_	| bct /= CTNull && ct /= bct -> do
				tlsFlush th
				setWBuf (clientId th) (ct, bs)
			| otherwise ->
				setWBuf (clientId th) (ct, bbs `BS.append` bs)
	case ct of
		ContentTypeHandshake -> updateHash (th, ctx) bs
		_ -> return (th, ctx)

generateKeys :: HandleLike h => CipherSuite ->
	BS.ByteString -> BS.ByteString -> BS.ByteString -> TlsM h g Keys
generateKeys cs cr sr pms = do
	let CipherSuite _ be = cs
	kl <- case be of
		AES_128_CBC_SHA -> return 20
		AES_128_CBC_SHA256 -> return 32
		_ -> throwError "TlsServer.generateKeys"
	let Right (ms, cwmk, swmk, cwk, swk) = makeKeys kl cr sr pms
	return Keys {
		kCachedCipherSuite = cs,
		kClientCipherSuite = CipherSuite KE_NULL BE_NULL,
		kServerCipherSuite = CipherSuite KE_NULL BE_NULL,
		kMasterSecret = ms,
		kClientWriteMacKey = cwmk,
		kServerWriteMacKey = swmk,
		kClientWriteKey = cwk,
		kServerWriteKey = swk }

cipherSuite :: TlsHandle h g -> CipherSuite
cipherSuite = kCachedCipherSuite . keys

setCipherSuite :: CipherSuite -> TlsHandle h g -> TlsHandle h g
setCipherSuite cs th@TlsHandle { keys = ks } =
	th { keys = ks { kCachedCipherSuite = cs } }

flushCipherSuite :: Partner -> TlsHandle h g -> TlsHandle h g
flushCipherSuite p th@TlsHandle { keys = ks } = case p of
	Client -> th { keys = ks { kClientCipherSuite = kCachedCipherSuite ks } }
	Server -> th { keys = ks { kServerCipherSuite = kCachedCipherSuite ks } }

data Partner = Server | Client deriving (Show, Eq)

handshakeHash :: HandleLike h => HandleHash h g -> TlsM h g BS.ByteString
handshakeHash = return . SHA256.finalize . snd

finishedHash :: HandleLike h => HandleHash h g -> Partner -> TlsM h g BS.ByteString
finishedHash (th, ctx) partner = do
	let ms = kMasterSecret $ keys th
	sha256 <- handshakeHash (th, ctx)
	return $ finishedHash_ (partner == Client) ms sha256

debugCipherSuite :: HandleLike h => TlsHandle h g -> String -> TlsM h g ()
debugCipherSuite th a = do
	let h = tlsHandle th
	thlDebug h 5 . BSC.pack
		. (++ (" - VERIFY WITH " ++ a ++ "\n")) . lenSpace 50
		. show . kCachedCipherSuite $ keys th
	where
	lenSpace n str = str ++ replicate (n - length str) ' '

write :: HandleLike h => TlsHandle h g -> BS.ByteString -> TlsM h g ()
write th = thlPut $ tlsHandle th

read :: (HandleLike h, CPRG g) => TlsHandle h g -> Int -> TlsM h g BS.ByteString
read h n = do
	tlsFlush h
	r <- flip thlGet n $ tlsHandle h
	if BS.length r == n
		then return r
		else throwError . strToAlert $ "Basic.read: bad reading: " ++
			show (BS.length r) ++ " " ++ show n

updateHash ::
	HandleLike h => HandleHash h g -> BS.ByteString -> TlsM h g (HandleHash h g)
updateHash (th, ctx') bs = return (th, SHA256.update ctx' bs)

updateSequenceNumber :: HandleLike h =>
	TlsHandle h g -> Partner -> Keys -> TlsM h g Word64
updateSequenceNumber th partner ks = do
	sn <- case partner of
		Client -> getClientSn $ clientId th
		Server -> getServerSn $ clientId th
	let	cs = pCipherSuite partner ks
	case cs of
		CipherSuite _ BE_NULL -> return ()
		_ -> case partner of
			Client -> succClientSn $ clientId th
			Server -> succServerSn $ clientId th
	return sn

pCipherSuite :: Partner -> Keys -> CipherSuite
pCipherSuite p = case p of
	Client -> kClientCipherSuite
	Server -> kServerCipherSuite

instance (HandleLike h, CPRG g) => HandleLike (TlsHandle h g) where
	type HandleMonad (TlsHandle h g) = TlsM h g
	type DebugLevel (TlsHandle h g) = DebugLevel h
	hlPut = ((>> return ()) .) . flip tlsPut ContentTypeApplicationData . (, undefined)
	hlGet = (.) <$> checkAppData <*> ((fst `liftM`) .) . tlsGet . (, undefined)
	hlGetLine = tGetLine
	hlGetContent = tGetContent
	hlDebug h l = lift . lift . hlDebug (tlsHandle h) l
	hlClose = tCloseSt

tlsFlush :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g ()
tlsFlush th = do
	(ct, bs) <- getWBuf $ clientId th
	setWBuf (clientId th) (CTNull, "")
	unless (ct == CTNull) $ do
		enc <- tlsEncryptMessage th (keys th) ct bs
		write th $ BS.concat [
			B.encode ct,
			B.encode (3 :: Word8),
			B.encode (3 :: Word8),
			B.encode (fromIntegral $ BS.length enc :: Word16),
			enc ]

tGetLine :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g BS.ByteString
tGetLine tc = do
	(mct, bfr) <- getBuf $ clientId tc
	case splitOneLine bfr of
		Just (l, ls) -> do
			setBuf (clientId tc) (mct, ls)
			return l
		_ -> do	msg <- tGetWhole tc
			setBuf (clientId tc) (ContentTypeApplicationData, msg)
			(bfr `BS.append`) `liftM` tGetLine tc

tGetContent :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g BS.ByteString
tGetContent tc = do
	(_, bfr) <- getBuf $ clientId tc
	if BS.null bfr then tGetWhole tc else do
		setBuf (clientId tc) (CTNull, BS.empty)
		return bfr

splitOneLine :: BS.ByteString -> Maybe (BS.ByteString, BS.ByteString)
splitOneLine bs = case ('\r' `BSC.elem` bs, '\n' `BSC.elem` bs) of
	(True, _) -> let
		(l, ls) = BSC.span (/= '\r') bs
		Just ('\r', ls') = BSC.uncons ls in
		case BSC.uncons ls' of
			Just ('\n', ls'') -> Just (l, ls'')
			_ -> Just (l, ls')
	(_, True) -> let
		(l, ls) = BSC.span (/= '\n') bs
		Just ('\n', ls') = BSC.uncons ls in Just (l, ls')
	_ -> Nothing

tCloseSt :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g ()
tCloseSt tc = do
	_ <- tlsPut (tc, undefined) ContentTypeAlert "\SOH\NUL"
	tlsFlush tc
	thlClose h
	where
	h = tlsHandle tc

tGetWhole :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g BS.ByteString
tGetWhole th = checkAppData th $ getWholeWithCt th

checkAppData :: (HandleLike h, CPRG g) => TlsHandle h g ->
	TlsM h g (ContentType, BS.ByteString) -> TlsM h g BS.ByteString
checkAppData th m = do
	ctbs <- m
	case ctbs of
		(ContentTypeApplicationData, ad) -> return ad
		(ContentTypeAlert, "\SOH\NUL") -> do
			_ <- tlsPut (th, undefined) ContentTypeAlert "\SOH\NUL"
			thlError (tlsHandle th) "tGetWhole: EOF"
		_ -> do	_ <- tlsPut (th, undefined) ContentTypeAlert "\2\10"
			throwError "not application data"

tlsDecryptMessage :: HandleLike h => TlsHandle h g ->
	Keys -> ContentType -> BS.ByteString -> TlsM h g BS.ByteString
tlsDecryptMessage _ Keys{ kClientCipherSuite = CipherSuite _ BE_NULL } _ enc =
	return enc
tlsDecryptMessage th ks ct enc = do
	let	CipherSuite _ be = pCipherSuite Client ks
		wk = kClientWriteKey ks
		mk = kClientWriteMacKey ks
	sn <- updateSequenceNumber th Client ks
	hs <- case be of
		AES_128_CBC_SHA -> return hashSha1
		AES_128_CBC_SHA256 -> return hashSha256
		_ -> throwError "bad"
	either (throwError . strMsg . show) return $ decryptMessage hs wk mk sn
		(B.encode ct `BS.append` "\x03\x03") enc

tlsEncryptMessage :: (HandleLike h, CPRG g) => TlsHandle h g ->
	Keys -> ContentType -> BS.ByteString -> TlsM h g BS.ByteString
tlsEncryptMessage _ Keys{ kServerCipherSuite = CipherSuite _ BE_NULL } _ msg =
	return msg
tlsEncryptMessage th ks ct msg = do
	let	CipherSuite _ be = pCipherSuite Server ks
		wk = kServerWriteKey ks
		mk = kServerWriteMacKey ks
	sn <- updateSequenceNumber th Server ks
	hs <- case be of
		AES_128_CBC_SHA -> return hashSha1
		AES_128_CBC_SHA256 -> return hashSha256
		_ -> throwError "bad"
	let enc = encryptMessage hs wk mk sn
		(B.encode ct `BS.append` "\x03\x03") msg
	withRandom enc
