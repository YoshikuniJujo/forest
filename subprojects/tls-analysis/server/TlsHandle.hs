{-# LANGUAGE OverloadedStrings, PackageImports, RankNTypes, TupleSections,
	FlexibleContexts, TypeFamilies #-}

module TlsHandle (
	TlsM, run, cipherSuite, setCipherSuite, CipherSuite(..),
	read, write, randomByteString, updateHash, handshakeHash,
	updateSequenceNumber,
	getContentType, buffered, withRandom, debugCipherSuite,

	Partner(..), Alert(..), AlertLevel(..), AlertDescription(..),
	
	flushCipherSuite,

	newHandle,

	ErrorType, Error, MonadError, throwError, lift, catchError,

	TlsClientState, initialTlsState,
	decryptMessage,
	hashSha1, hashSha256, encryptMessage,
	ContentType(..),
	TlsHandle(..), Keys,
	finishedHash, generateKeys,

	tlsGetContentType, tlsGet, tlsPut,
) where

import Prelude hiding (read)

import Control.Applicative
import Control.Monad
import Data.Word
import Data.HandleLike
import "crypto-random" Crypto.Random
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error.Class

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import TlsMonad
import CryptoTools

import qualified Codec.Bytable as B

import qualified Crypto.Hash.SHA256 as SHA256

cipherSuite :: TlsHandle h g -> CipherSuite
cipherSuite = kCachedCipherSuite . keys

setCipherSuite :: CipherSuite -> TlsHandle h g -> TlsHandle h g
setCipherSuite cs th@TlsHandle { keys = ks } =
	th { keys = ks { kCachedCipherSuite = cs } }

randomByteString :: (HandleLike h, CPRG g) => Int -> TlsM h g BS.ByteString
randomByteString len = withRandom $ cprgGenerate len

flushCipherSuite :: Partner -> TlsHandle h g -> TlsHandle h g
flushCipherSuite p th@TlsHandle { keys = ks } = case p of
	Client -> th { keys = ks { kClientCipherSuite = kCachedCipherSuite ks } }
	Server -> th { keys = ks { kServerCipherSuite = kCachedCipherSuite ks } }

data Partner = Server | Client deriving (Show, Eq)

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

handshakeHash :: HandleLike h =>
	(TlsHandle h g, SHA256.Ctx) -> TlsM h g BS.ByteString
handshakeHash = return . SHA256.finalize . snd

updateHash :: HandleLike h => (TlsHandle h g, SHA256.Ctx) ->
	BS.ByteString -> TlsM h g (TlsHandle h g, SHA256.Ctx)
updateHash (th@TlsHandle { handshakeHashCtx = ctx }, ctx') bs =
	return (th { handshakeHashCtx = SHA256.update ctx bs }, SHA256.update ctx' bs)

getContentType :: HandleLike h => TlsHandle h g ->
	TlsM h g (ContentType, BS.ByteString) -> TlsM h g ContentType
getContentType th rd = do
	mct <- fst `liftM` getBuf (clientId th)
	(\gt -> case mct of ContentTypeNull -> gt; _ -> return mct) $ do
		(ct, bf) <- rd
		setBuf (clientId th) (ct, bf)
		return ct

buffered :: HandleLike h =>
	TlsHandle h g -> Int -> TlsM h g (ContentType, BS.ByteString) ->
	TlsM h g (ContentType, BS.ByteString)
buffered th n rd = do
	(mct, bf) <- getBuf $ clientId th
	if BS.length bf >= n
	then do	let (ret, bf') = BS.splitAt n bf
		setBuf (clientId th) $
			if BS.null bf' then (ContentTypeNull, "") else (mct, bf')
		return (mct, ret)
	else do	(ct', bf') <- rd
		unless (ct' == mct) .
			throwError . strToAlert $ "Content Type confliction\n" ++
				"\tExpected: " ++ show mct ++ "\n" ++
				"\tActual  : " ++ show ct' ++ "\n" ++
				"\tData    : " ++ show bf'
		when (BS.null bf') $ throwError "buffered: No data available"
		setBuf (clientId th) (ct', bf')
		((ct' ,) . (bf `BS.append`) . snd) `liftM` buffered th (n - BS.length bf) rd

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

debugCipherSuite :: HandleLike h => TlsHandle h g -> String -> TlsM h g ()
debugCipherSuite th a = do
	let h = tlsHandle th
	thlDebug h 5 . BSC.pack
		. (++ (" - VERIFY WITH " ++ a ++ "\n")) . lenSpace 50
		. show . kCachedCipherSuite $ keys th
	where
	lenSpace n str = str ++ replicate (n - length str) ' '

data TlsHandle h g = TlsHandle {
	clientId :: ClientId,
	clientNames :: [String],
	tlsHandle :: h,
	keys :: Keys,
	handshakeHashCtx :: SHA256.Ctx }

newHandle :: HandleLike h => h -> TlsM h g (TlsHandle h g)
newHandle h = do
	s <- get
	let (cid, s') = newClientId s
	put s'
	return TlsHandle {
		clientId = cid, clientNames = [], tlsHandle = h, keys = nullKeys,
		handshakeHashCtx = SHA256.init }

instance (HandleLike h, CPRG g) => HandleLike (TlsHandle h g) where
	type HandleMonad (TlsHandle h g) = TlsM h g
	type DebugLevel (TlsHandle h g) = DebugLevel h
	hlPut = ((>> return ()) .) . flip tlsPut ContentTypeApplicationData . (, undefined)
	hlGet = (.) <$> checkAppData <*> ((fst `liftM`) .) . tlsGet . (, undefined)
	hlGetLine = tGetLine
	hlGetContent = tGetContent
	hlDebug h l = lift . lift . hlDebug (tlsHandle h) l
	hlClose = tCloseSt

tlsPut :: (HandleLike h, CPRG g) => (TlsHandle h g, SHA256.Ctx) ->
	ContentType -> BS.ByteString -> TlsM h g (TlsHandle h g, SHA256.Ctx)
tlsPut (th, ctx) ct bs = do
	(bct, bbs) <- getWBuf $ clientId th
	case ct of
		ContentTypeChangeCipherSpec -> do
				tlsFlush th
				setWBuf (clientId th) (ct, bs)
				tlsFlush th
				return ()
		_	| bct /= ContentTypeNull && ct /= bct -> do
				tlsFlush th
				setWBuf (clientId th) (ct, bs)
			| otherwise ->
				setWBuf (clientId th) (ct, bbs `BS.append` bs)
	case ct of
		ContentTypeHandshake -> updateHash (th, ctx) bs
		_ -> return (th, ctx)

tlsFlush :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g ()
tlsFlush th = do
	(ct, bs) <- getWBuf $ clientId th
	setWBuf (clientId th) (ContentTypeNull, "")
	unless (ct == ContentTypeNull) $ do
		enc <- tlsEncryptMessage th (keys th) ct bs
		write th $ BS.concat [
			B.toByteString ct,
			B.toByteString (3 :: Word8),
			B.toByteString (3 :: Word8),
			B.toByteString (fromIntegral $ BS.length enc :: Word16),
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
		setBuf (clientId tc) (ContentTypeNull, BS.empty)
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

tlsGet, readByteString :: (HandleLike h, CPRG g) =>
	(TlsHandle h g, SHA256.Ctx) -> Int ->
	TlsM h g ((ContentType, BS.ByteString), (TlsHandle h g, SHA256.Ctx))
tlsGet = readByteString
readByteString (th, ctx) n = do
	(ct, bs) <- buffered th n $ tGetWholeWithCt th
	th' <- case ct of
		ContentTypeHandshake -> updateHash (th, ctx) bs
		_ -> return (th, ctx)
	return ((ct, bs), th')

tGetWhole :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g BS.ByteString
tGetWhole th = checkAppData th $ tGetWholeWithCt th

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

tGetWholeWithCt :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> TlsM h g (ContentType, BS.ByteString)
tGetWholeWithCt th = do
	ct <- (either error id . B.fromByteString) `liftM` read th 1
	[_vmjr, _vmnr] <- BS.unpack `liftM` read th 2
	ebody <- read th . either error id . B.fromByteString =<< read th 2
	when (BS.null ebody) $ throwError "tGetWholeWithCt: ebody is null"
	body <- tlsDecryptMessage th (keys th) ct ebody
	return (ct, body)

tlsGetContentType :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g ContentType
tlsGetContentType th = getContentType th $ tGetWholeWithCt th

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
		(B.toByteString ct `BS.append` "\x03\x03") enc

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
		(B.toByteString ct `BS.append` "\x03\x03") msg
	withRandom enc

finishedHash :: HandleLike h =>
	(TlsHandle h g, SHA256.Ctx) -> Partner -> TlsM h g BS.ByteString
finishedHash (th, ctx) partner = do
	let ms = kMasterSecret $ keys th
	sha256 <- handshakeHash (th, ctx)
	return $ finishedHash_ (partner == Client) ms sha256

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
