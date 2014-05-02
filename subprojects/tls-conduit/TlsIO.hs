{-# LANGUAGE PackageImports #-}

module TlsIO (
	TlsIO, runTlsIO, evalTlsIO, initTlsState, liftIO,
	Partner(..), ServerHandle(..), ClientHandle(..),
	read, write, readLen, writeLen,

	setClientRandom, setServerRandom, decryptRSA,
	generateMasterSecret,

	masterSecret, expandedMasterSecret,

	debugPrintKeys,

	Handle, Word8, ByteString, BS.unpack, BS.pack
) where

import Prelude hiding (read)

import Control.Applicative
import Numeric

import System.IO
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.State

import Data.Word
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15

import qualified MasterSecret as MS
import Parts
import Tools

type TlsIO = ErrorT String (StateT TlsState IO)

data TlsState = TlsState {
	tlssServerHandle :: Handle,
	tlssClientHandle :: Handle,
	tlssPrivateKey :: PrivateKey,
	tlssCipherSuite :: CipherSuite,
	tlssCachedCipherSuite :: Maybe CipherSuite,
	tlssClientRandom :: Maybe ByteString,
	tlssServerRandom :: Maybe ByteString,
	tlssMasterSecret :: Maybe ByteString,
	tlssExpandedMasterSecret :: Maybe ByteString,
	tlssClientWriteMacKey :: Maybe ByteString,
	tlssServerWriteMacKey :: Maybe ByteString,
	tlssClientWriteKey :: Maybe ByteString,
	tlssServerWriteKey :: Maybe ByteString,
	tlssClientWriteIv :: Maybe ByteString,
	tlssServerWriteIv :: Maybe ByteString
 } deriving Show

data ServerHandle = ServerHandle Handle deriving Show
data ClientHandle = ClientHandle Handle deriving Show

initTlsState :: ClientHandle -> ServerHandle -> PrivateKey -> TlsState
initTlsState (ClientHandle cl) (ServerHandle sv) pk = TlsState {
	tlssServerHandle = sv,
	tlssClientHandle = cl,
	tlssPrivateKey = pk,
	tlssCipherSuite = TLS_NULL_WITH_NULL_NULL,
	tlssCachedCipherSuite = Nothing,
	tlssClientRandom = Nothing,
	tlssServerRandom = Nothing,
	tlssMasterSecret = Nothing,
	tlssExpandedMasterSecret = Nothing,
	tlssClientWriteMacKey = Nothing,
	tlssServerWriteMacKey = Nothing,
	tlssClientWriteKey = Nothing,
	tlssServerWriteKey = Nothing,
	tlssClientWriteIv = Nothing,
	tlssServerWriteIv = Nothing
 }

data Partner = Server | Client deriving Show

handle :: Partner -> TlsState -> Handle
handle Server = tlssServerHandle
handle Client = tlssClientHandle

runTlsIO :: TlsIO a -> TlsState -> IO (Either String a, TlsState)
runTlsIO io ts = runErrorT io `runStateT` ts

evalTlsIO :: TlsIO a -> ClientHandle -> ServerHandle -> PrivateKey -> IO a
evalTlsIO io cl sv pk = do
	ret <- runErrorT io `evalStateT` initTlsState cl sv pk
	case ret of
		Right r -> return r
		Left err -> error err

read :: Partner -> Int -> TlsIO ByteString
read partner n = do
	h <- gets $ handle partner
	r <- liftIO $ BS.hGet h n
	if BS.length r == n
		then return r
		else throwError $ "Basic.read: bad reading: " ++
			show (BS.length r) ++ " " ++ show n

write :: Partner -> ByteString -> TlsIO ()
write partner dat = do
	h <- gets $ handle partner
	liftIO $ BS.hPut h dat

readLen :: Partner -> Int -> TlsIO ByteString
readLen partner n = do
	len <- read partner n
	read partner $ byteStringToInt len

writeLen :: Partner -> Int -> ByteString -> TlsIO ()
writeLen partner n bs = do
	write partner $ intToByteString n $ BS.length bs
	write partner bs

decryptRSA :: ByteString -> TlsIO ByteString
decryptRSA e = do
	pk <- gets tlssPrivateKey
	case decrypt Nothing pk e of
		Right d -> return d
		Left err -> throwError $ show err

setClientRandom, setServerRandom :: ByteString -> TlsIO ()
setClientRandom cr = do
	tlss <- get
	put $ tlss { tlssClientRandom = Just cr }
setServerRandom sr = do
	tlss <- get
	put $ tlss { tlssServerRandom = Just sr }

generateMasterSecret :: ByteString -> TlsIO ()
generateMasterSecret pms = do
	mcr <- gets $ (MS.ClientRandom <$>) . tlssClientRandom
	msr <- gets $ (MS.ServerRandom <$>) . tlssServerRandom
	case (mcr, msr) of
		(Just cr, Just sr) -> do
			let	ms = MS.masterSecret pms cr sr
				ems = MS.keyBlock cr sr ms 104
				[cwmk, swmk, cwk, swk, cwi, swi] =
					divide [
						20, 20,
						16, 16,
						16, 16 ] ems
			tlss <- get
			put $ tlss {
				tlssMasterSecret = Just ms,
				tlssExpandedMasterSecret = Just ems,
				tlssClientWriteMacKey = Just cwmk,
				tlssServerWriteMacKey = Just swmk,
				tlssClientWriteKey = Just cwk,
				tlssServerWriteKey = Just swk,
				tlssClientWriteIv = Just cwi,
				tlssServerWriteIv = Just swi
			 }
		_ -> throwError "No client random / No server random"

masterSecret :: TlsIO (Maybe ByteString)
masterSecret = gets tlssMasterSecret

expandedMasterSecret :: TlsIO (Maybe ByteString)
expandedMasterSecret = gets tlssExpandedMasterSecret

divide :: [Int] -> BS.ByteString -> [BS.ByteString]
divide [] _ = []
divide (n : ns) bs
	| bs == BS.empty = []
	| otherwise = let (x, xs) = BS.splitAt n bs in x : divide ns xs

debugPrintKeys :: TlsIO ()
debugPrintKeys = do
	Just cwmk <- gets tlssClientWriteMacKey
	Just swmk <- gets tlssServerWriteMacKey
	Just cwk <- gets tlssClientWriteKey
	Just swk <- gets tlssServerWriteKey
	Just cwi <- gets tlssClientWriteIv
	Just swi <- gets tlssServerWriteIv
	liftIO $ do
		putStrLn $ "###### GENERATED KEYS ######"
		putStrLn $ "Client Write MAC Key: " ++ showKey cwmk
		putStrLn $ "Server Write MAC Key: " ++ showKey swmk
		putStrLn $ "Client Write Key    : " ++ showKey cwk
		putStrLn $ "Server Write Key    : " ++ showKey swk
		putStrLn $ "Client Write IV     : " ++ showKey cwi
		putStrLn $ "Server Write IV     : " ++ showKey swi

showKey :: ByteString -> String
showKey = unwords . map showH . BS.unpack

showH :: Word8 -> String
showH w = replicate (2 - length s) '0' ++ s
	where
	s = showHex w ""
