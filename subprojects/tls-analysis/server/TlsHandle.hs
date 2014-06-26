{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, PackageImports #-}

module TlsHandle (
	TlsM, Alert(..), AlertLevel(..), AlertDesc(..),
		run, withRandom, randomByteString,
	TlsHandle(..), Partner(..), ContentType(..), CipherSuite(..),
		newHandle, getContentType, tlsGet, tlsPut, generateKeys,
		cipherSuite, setCipherSuite, flushCipherSuite, debugCipherSuite,
		handshakeHash, finishedHash ) where

import Prelude hiding (read)

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (second)
import Control.Monad (liftM, when, unless)
import "monads-tf" Control.Monad.State (get, put, lift)
import "monads-tf" Control.Monad.Error (throwError, catchError)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.Word (Word16, Word64)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Codec.Bytable as B
import qualified Crypto.Hash.SHA256 as SHA256

import TlsMonad (
	TlsM, evalTlsM, initState, thlGet, thlPut, thlClose, thlDebug,
		withRandom, randomByteString, getBuf, setBuf, getWBuf, setWBuf,
		getClientSn, getServerSn, succClientSn, succServerSn,
	Alert(..), AlertLevel(..), AlertDesc(..),
	ContentType(..), CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	ClientId, newClientId, Keys(..), nullKeys )
import qualified CryptoTools as CT (
	makeKeys, encrypt, decrypt, hashSha1, hashSha256, finishedHash )

data TlsHandle h g = TlsHandle {
	clientId :: ClientId,
	tlsHandle :: h, keys :: Keys, clientNames :: [String] }

type HandleHash h g = (TlsHandle h g, SHA256.Ctx)

data Partner = Server | Client deriving (Show, Eq)

run :: HandleLike h => TlsM h g a -> g -> HandleMonad h a
run m g = do
	ret <- (`evalTlsM` initState g) $ m `catchError` \a -> throwError a
	case ret of
		Right r -> return r
		Left a -> error $ show a

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
		CTHandshake -> updateHash hh bs
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
		unless (ct' == ct) . throwError . strMsg $
			"Content Type confliction\n" ++
				"\tExpected: " ++ show ct ++ "\n" ++
				"\tActual  : " ++ show ct' ++ "\n" ++
				"\tData    : " ++ show b'
		when (BS.null b') $ throwError "buffered: No data available"
		setBuf (clientId t) (ct', b')
		second (b `BS.append`) `liftM` buffered t rl

getWholeWithCt :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> TlsM h g (ContentType, BS.ByteString)
getWholeWithCt t = do
	flush t
	ct <- (either (throwError . strMsg) return . B.decode) =<< read t 1
	[_vmj, _vmn] <- BS.unpack `liftM` read t 2
	e <- read t =<< either (throwError . strMsg) return . B.decode =<< read t 2
	when (BS.null e) $ throwError "TlsHandle.getWholeWithCt: e is null"
	p <- decrypt t ct e
	return (ct, p)

read :: (HandleLike h, CPRG g) => TlsHandle h g -> Int -> TlsM h g BS.ByteString
read t n = do
	r <- thlGet (tlsHandle t) n
	unless (BS.length r == n) . throwError . strMsg $
		"TlsHandle.read: can't read " ++ show (BS.length r) ++ " " ++ show n
	return r

decrypt :: HandleLike h =>
	TlsHandle h g -> ContentType -> BS.ByteString -> TlsM h g BS.ByteString
decrypt t _ e
	| Keys{ kClientCS = CipherSuite _ BE_NULL } <- keys t = return e
decrypt t@TlsHandle{ keys = ks } ct e = do
	let	CipherSuite _ be = kClientCS ks
		wk = kCWKey ks
		mk = kCWMacKey ks
	sn <- updateSequenceNumber t Client
	hs <- case be of
		AES_128_CBC_SHA -> return CT.hashSha1
		AES_128_CBC_SHA256 -> return CT.hashSha256
		_ -> throwError "TlsHandle.decrypt: not implement bulk encryption"
	either (throwError . strMsg . show) return $
		CT.decrypt hs wk mk sn (B.encode ct `BS.append` "\x03\x03") e

tlsPut :: (HandleLike h, CPRG g) =>
	HandleHash h g -> ContentType -> BS.ByteString -> TlsM h g (HandleHash h g)
tlsPut hh@(t, _) ct p = do
	(bct, bp) <- getWBuf $ clientId t
	case ct of
		CTCCSpec -> flush t >> setWBuf (clientId t) (ct, p) >> flush t
		_	| bct /= CTNull && ct /= bct ->
				flush t >> setWBuf (clientId t) (ct, p)
			| otherwise -> setWBuf (clientId t) (ct, bp `BS.append` p)
	case ct of
		CTHandshake -> updateHash hh p
		_ -> return hh

flush :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g ()
flush t = do
	(bct, bp) <- getWBuf $ clientId t
	setWBuf (clientId t) (CTNull, "")
	unless (bct == CTNull) $ do
		e <- encrypt t bct bp
		thlPut (tlsHandle t) $ BS.concat [
			B.encode bct, "\x03\x03", B.addLen (undefined :: Word16) e ]

encrypt :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> ContentType -> BS.ByteString -> TlsM h g BS.ByteString
encrypt t _ p
	| Keys{ kServerCS = CipherSuite _ BE_NULL } <- keys t = return p
encrypt t@TlsHandle{ keys = ks } ct p = do
	let	CipherSuite _ be = kServerCS ks
		wk = kSWKey ks
		mk = kSWMacKey ks
	sn <- updateSequenceNumber t Server
	hs <- case be of
		AES_128_CBC_SHA -> return CT.hashSha1
		AES_128_CBC_SHA256 -> return CT.hashSha256
		_ -> throwError "TlsHandle.encrypt: not implemented bulk encryption"
	withRandom $ CT.encrypt hs wk mk sn (B.encode ct `BS.append` "\x03\x03") p

updateHash ::
	HandleLike h => HandleHash h g -> BS.ByteString -> TlsM h g (HandleHash h g)
updateHash (th, ctx') bs = return (th, SHA256.update ctx' bs)

updateSequenceNumber :: HandleLike h => TlsHandle h g -> Partner -> TlsM h g Word64
updateSequenceNumber t@TlsHandle{ keys = ks } p = do
	(sn, cs) <- case p of
		Client -> (, kClientCS ks) `liftM` getClientSn (clientId t)
		Server -> (, kServerCS ks) `liftM` getServerSn (clientId t)
	case cs of
		CipherSuite _ BE_NULL -> return ()
		_ -> case p of
			Client -> succClientSn $ clientId t
			Server -> succServerSn $ clientId t
	return sn

generateKeys :: HandleLike h => CipherSuite ->
	BS.ByteString -> BS.ByteString -> BS.ByteString -> TlsM h g Keys
generateKeys cs cr sr pms = do
	let CipherSuite _ be = cs
	kl <- case be of
		AES_128_CBC_SHA -> return 20
		AES_128_CBC_SHA256 -> return 32
		_ -> throwError
			"TlsServer.generateKeys: not implemented bulk encryption"
	let (ms, cwmk, swmk, cwk, swk) = CT.makeKeys kl cr sr pms
	return Keys {
		kCachedCS = cs,
		kClientCS = CipherSuite KE_NULL BE_NULL,
		kServerCS = CipherSuite KE_NULL BE_NULL,
		kMasterSecret = ms,
		kCWMacKey = cwmk, kSWMacKey = swmk, kCWKey = cwk, kSWKey = swk }

cipherSuite :: TlsHandle h g -> CipherSuite
cipherSuite = kCachedCS . keys

setCipherSuite :: CipherSuite -> TlsHandle h g -> TlsHandle h g
setCipherSuite c t@TlsHandle{ keys = k } = t{ keys = k{ kCachedCS = c } }

flushCipherSuite :: Partner -> TlsHandle h g -> TlsHandle h g
flushCipherSuite p t@TlsHandle{ keys = ks } = case p of
	Client -> t{ keys = ks { kClientCS = kCachedCS ks } }
	Server -> t{ keys = ks { kServerCS = kCachedCS ks } }

debugCipherSuite :: HandleLike h => TlsHandle h g -> String -> TlsM h g ()
debugCipherSuite t a = thlDebug (tlsHandle t) 5 . BSC.pack
	. (++ (" - VERIFY WITH " ++ a ++ "\n")) . lenSpace 50
	. show . kCachedCS $ keys t
	where lenSpace n str = str ++ replicate (n - length str) ' '

handshakeHash :: HandleLike h => HandleHash h g -> TlsM h g BS.ByteString
handshakeHash = return . SHA256.finalize . snd

finishedHash :: HandleLike h => HandleHash h g -> Partner -> TlsM h g BS.ByteString
finishedHash (t, ctx) partner = do
	let ms = kMasterSecret $ keys t
	sha256 <- handshakeHash (t, ctx)
	return $ CT.finishedHash (partner == Client) ms sha256

instance (HandleLike h, CPRG g) => HandleLike (TlsHandle h g) where
	type HandleMonad (TlsHandle h g) = TlsM h g
	type DebugLevel (TlsHandle h g) = DebugLevel h
	hlPut = ((>> return ()) .) . flip tlsPut CTAppData . (, undefined)
	hlGet = (.) <$> checkAppData <*> ((fst `liftM`) .) . tlsGet . (, undefined)
	hlGetLine = ($) <$> checkAppData <*> tGetLine
	hlGetContent = ($) <$> checkAppData <*> tGetContent
	hlDebug t l = lift . lift . hlDebug (tlsHandle t) l
	hlClose t = tlsPut (t, undefined) CTAlert "\SOH\NUL" >>
		flush t >> thlClose (tlsHandle t)

tGetLine :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> TlsM h g (ContentType, BS.ByteString)
tGetLine t = do
	(bct, bp) <- getBuf $ clientId t
	case splitLine bp of
		Just (l, ls) -> setBuf (clientId t) (bct, ls) >> return (bct, l)
		_ -> do	cp <- getWholeWithCt t
			setBuf (clientId t) cp
			second (bp `BS.append`) `liftM` tGetLine t

splitLine :: BS.ByteString -> Maybe (BS.ByteString, BS.ByteString)
splitLine bs = case ('\r' `BSC.elem` bs, '\n' `BSC.elem` bs) of
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

tGetContent :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> TlsM h g (ContentType, BS.ByteString)
tGetContent t = do
	bcp@(_, bp) <- getBuf $ clientId t
	if BS.null bp then getWholeWithCt t else
		setBuf (clientId t) (CTNull, BS.empty) >> return bcp

checkAppData :: (HandleLike h, CPRG g) => TlsHandle h g ->
	TlsM h g (ContentType, BS.ByteString) -> TlsM h g BS.ByteString
checkAppData t m = m >>= \cp -> case cp of
	(CTAppData, ad) -> return ad
	(CTAlert, "\SOH\NUL") -> do
		_ <- tlsPut (t, undefined) CTAlert "\SOH\NUL"
		throwError "TlsHandle.checkAppData: EOF"
	_ -> do	_ <- tlsPut (t, undefined) CTAlert "\2\10"
		throwError "TlsHandle.checkAppData: not application data"
