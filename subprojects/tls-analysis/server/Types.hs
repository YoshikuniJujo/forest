{-# LANGUAGE OverloadedStrings, PackageImports, ScopedTypeVariables,
	FlexibleInstances, TypeFamilies, TupleSections #-}

module Types (
	Bytable(..),

	Version(..), byteStringToVersion, versionToByteString,
	ContentType(..), byteStringToContentType, contentTypeToByteString,
	Random(..), CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),

	NamedCurve(..),

	SignatureAlgorithm(..),
	HashAlgorithm(..),
	Parsable(..),
	Parsable'(..),
	Parsable''(..),

	lenBodyToByteString, Word8, headBS,

	word16ToByteString,
	word64ToByteString,

	intToByteString,
	byteStringToInt,
	takeLen,
	takeLen',
	evalByteStringM,

	takeWords, takeWords',
	takeBS,
	ByteStringM,
	section,
	emptyBS,
	whole,

	namedCurveToByteString,
	list,
	list1,
--	parseNamedCurve,
	section',
	throwError,

	splitLen,
	list',
) where

import Control.Arrow
import Data.Word
import qualified Data.ByteString as BS
-- import ByteStringMonad

import Prelude hiding (head, take)
import qualified Prelude

import Control.Applicative ((<$>), (<*>))

import Data.Bits
import Data.ByteString (ByteString)
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error

import Numeric

import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()

data Version
	= Version Word8 Word8
	deriving (Show, Eq, Ord)

byteStringToVersion :: BS.ByteString -> Version
byteStringToVersion v = let [vmjr, vmnr] = BS.unpack v in Version vmjr vmnr

versionToByteString :: Version -> BS.ByteString
versionToByteString (Version vmjr vmnr) = BS.pack [vmjr, vmnr]

data ContentType
	= ContentTypeChangeCipherSpec
	| ContentTypeAlert
	| ContentTypeHandshake
	| ContentTypeApplicationData
	| ContentTypeRaw Word8
	deriving (Show, Eq)

byteStringToContentType :: BS.ByteString -> ContentType
byteStringToContentType "" = error "Types.byteStringToContentType: empty"
byteStringToContentType "\20" = ContentTypeChangeCipherSpec
byteStringToContentType "\21" = ContentTypeAlert
byteStringToContentType "\22" = ContentTypeHandshake
byteStringToContentType "\23" = ContentTypeApplicationData
byteStringToContentType bs = let [ct] = BS.unpack bs in ContentTypeRaw ct

contentTypeToByteString :: ContentType -> BS.ByteString
contentTypeToByteString ContentTypeChangeCipherSpec = BS.pack [20]
contentTypeToByteString ContentTypeAlert = BS.pack [21]
contentTypeToByteString ContentTypeHandshake = BS.pack [22]
contentTypeToByteString ContentTypeApplicationData = BS.pack [23]
contentTypeToByteString (ContentTypeRaw ct) = BS.pack [ct]

data Random = Random BS.ByteString

data CipherSuiteKeyEx
	= RSA
	| DHE_RSA
	| ECDHE_RSA
	| ECDHE_ECDSA
	| ECDHE_PSK
	| KeyExNULL
	deriving (Show, Read, Eq)

data CipherSuiteMsgEnc
	= AES_128_CBC_SHA
	| AES_128_CBC_SHA256
	| CAMELLIA_128_CBC_SHA
	| NULL_SHA
	| MsgEncNULL
	deriving (Show, Read, Eq)

data CipherSuite
	= CipherSuite CipherSuiteKeyEx CipherSuiteMsgEnc
	| CipherSuiteRaw Word8 Word8
	deriving (Show, Read, Eq)

data NamedCurve
	= Secp256r1
	| Secp384r1
	| Secp521r1
	| NamedCurveRaw Word16
	deriving Show

data SignatureAlgorithm
	= SignatureAlgorithmRsa
	| SignatureAlgorithmDsa
	| SignatureAlgorithmEcdsa
	| SignatureAlgorithmRaw Word8
	deriving Show

data HashAlgorithm
	= HashAlgorithmSha1
	| HashAlgorithmSha224
	| HashAlgorithmSha256
	| HashAlgorithmSha384
	| HashAlgorithmSha512
	| HashAlgorithmRaw Word8
	deriving Show

instance Parsable HashAlgorithm where
	parse = parseHashAlgorithm
	toByteString = hashAlgorithmToByteString
	listLength _ = Just 1

parseHashAlgorithm :: ByteStringM HashAlgorithm
parseHashAlgorithm = do
	ha <- headBS
	return $ case ha of
		2 -> HashAlgorithmSha1
		3 -> HashAlgorithmSha224
		4 -> HashAlgorithmSha256
		5 -> HashAlgorithmSha384
		6 -> HashAlgorithmSha512
		_ -> HashAlgorithmRaw ha

hashAlgorithmToByteString :: HashAlgorithm -> ByteString
hashAlgorithmToByteString HashAlgorithmSha1 = "\x02"
hashAlgorithmToByteString HashAlgorithmSha224 = "\x03"
hashAlgorithmToByteString HashAlgorithmSha256 = "\x04"
hashAlgorithmToByteString HashAlgorithmSha384 = "\x05"
hashAlgorithmToByteString HashAlgorithmSha512 = "\x06"
hashAlgorithmToByteString (HashAlgorithmRaw w) = BS.pack [w]

instance Parsable SignatureAlgorithm where
	parse = parseSignatureAlgorithm
	toByteString = signatureAlgorithmToByteString
	listLength _ = Just 1

parseSignatureAlgorithm :: ByteStringM SignatureAlgorithm
parseSignatureAlgorithm = do
	sa <- headBS
	return $ case sa of
		1 -> SignatureAlgorithmRsa
		2 -> SignatureAlgorithmDsa
		3 -> SignatureAlgorithmEcdsa
		_ -> SignatureAlgorithmRaw sa

signatureAlgorithmToByteString :: SignatureAlgorithm -> ByteString
signatureAlgorithmToByteString SignatureAlgorithmRsa = "\x01"
signatureAlgorithmToByteString SignatureAlgorithmDsa = "\x02"
signatureAlgorithmToByteString SignatureAlgorithmEcdsa = "\x03"
signatureAlgorithmToByteString (SignatureAlgorithmRaw w) = BS.pack [w]

{-
instance Parsable NamedCurve where
	parse = parseNamedCurve
	toByteString = namedCurveToByteString
	listLength _ = Nothing

parseNamedCurve :: ByteStringM NamedCurve
parseNamedCurve = either error id . byteStringToNamedCurve <$> takeBS 2
	-}

instance B.Bytable NamedCurve where
	fromByteString = byteStringToNamedCurve
	toByteString = namedCurveToByteString

byteStringToNamedCurve :: ByteString -> Either String NamedCurve
byteStringToNamedCurve bs = case BS.unpack bs of
	[w1, w2] -> Right $ case fromIntegral w1 `shiftL` 8 .|. fromIntegral w2 of
		23 -> Secp256r1
		24 -> Secp384r1
		25 -> Secp521r1
		nc -> NamedCurveRaw nc
	_ -> Left "Types.byteStringToNamedCurve"

namedCurveToByteString :: NamedCurve -> ByteString
namedCurveToByteString (Secp256r1) = word16ToByteString 23
namedCurveToByteString (Secp384r1) = word16ToByteString 24
namedCurveToByteString (Secp521r1) = word16ToByteString 25
namedCurveToByteString (NamedCurveRaw nc) = word16ToByteString nc

class Parsable a where
	parse :: ByteStringM a
	toByteString :: a -> ByteString
	listLength :: a -> Maybe Int

class Parsable' a where
	parse' :: Monad m => (Int -> m BS.ByteString) -> m a
	toByteString' :: a -> ByteString

class Parsable'' a where
	parse'' :: BS.ByteString -> Either String (a, BS.ByteString)
	toByteString'' :: a -> ByteString

class Bytable a where
	fromByteString :: BS.ByteString -> Either String a
	toByteString_ :: a -> ByteString

type Parse a = BS.ByteString -> Either String (a, BS.ByteString)

list' :: Parse a -> BS.ByteString -> Either String [a]
list' _ bs | BS.null bs = Right []
list' prs bs = do
	(x, r) <- prs bs
	case r of
		"" -> return [x]
		_ -> (x :) <$> list' prs r

class Endable m where
	isEnd :: m Bool

instance Endable ByteStringM where
	isEnd = BS.null `liftM` get

instance Parsable a => Parsable [a] where
	parse = case listLength (undefined :: a) of
		Just n -> section n $ list parse
		_ -> list parse
	toByteString = case listLength (undefined :: a) of
		Just n -> lenBodyToByteString n . BS.concat . map toByteString
		_ -> error "Parsable [a]: Not set list len"
	listLength _ = Nothing

splitLen :: Int -> BS.ByteString -> Either String (BS.ByteString, BS.ByteString)
splitLen n bs = do
	unless (BS.length bs >= n) $ Left "Types.splitLen"
	let (l, bs') = first byteStringToInt $ BS.splitAt n bs
	unless (BS.length bs' >= l) $ Left "Types.splitLen"
	return $ BS.splitAt l bs'

instance (Parsable a, Parsable b) => Parsable (a, b) where
	parse = (,) <$> parse <*> parse
	toByteString (x, y) = toByteString x `BS.append` toByteString y
	listLength _ = (+)
		<$> listLength (undefined :: a)
		<*> listLength (undefined :: b)

type ByteStringM = ErrorT String (State ByteString)

evalByteStringM :: ByteStringM a -> ByteString -> Either String a
evalByteStringM m bs = case runState (runErrorT m) bs of
	(Right x, "") -> Right x
	(Right _, rest) -> Left $ "rest: " ++ show rest
	(err, _) -> err

headBS :: ByteStringM Word8
headBS = do
	msep <- lift $ gets BS.uncons
	case msep of
		Just (h, t) -> lift (put t) >> return h
		_ -> throwError "ByteStringMonad.head"

takeBS :: Int -> ByteStringM ByteString
takeBS len = do
	(t, d) <- lift $ gets (BS.splitAt len)
	if BS.length t /= len
	then throwError $ "ByteStringMonad.takeBS:\n" ++
		"expected: " ++ show len ++ "bytes\n" ++
		"actual  : " ++ show (BS.length t) ++ "bytes\n"
	else do
		lift $ put d
		return t

takeWords :: Int -> ByteStringM [Word8]
takeWords = (BS.unpack <$>) . takeBS

takeWords' :: Monad m => (Int -> m BS.ByteString) -> Int -> m [Word8]
takeWords' = ((BS.unpack `liftM`) .)

takeInt' :: Monad m => (Int -> m BS.ByteString) -> Int -> m Int
takeInt' rd = (byteStringToInt `liftM`) . rd

takeInt :: Int -> ByteStringM Int
takeInt = (byteStringToInt <$>) . takeBS

takeLen :: Int -> ByteStringM ByteString
takeLen n = do
	len <- takeInt n
	takeBS len

emptyBS :: ByteStringM Bool
emptyBS = (== BS.empty) <$> get

list1 :: (Monad m, Endable m) => m a -> m [a]
list1 m = do
	x <- m
	e <- isEnd
	if e then return [x] else (x :) `liftM` list1 m

list :: (Monad m, Endable m) => m a -> m [a]
list m = do
	e <- isEnd
	if e then return [] else (:) `liftM` m `ap` list m

takeLen' :: Monad m => (Int -> m BS.ByteString) -> Int -> m ByteString
takeLen' rd n = do
	l <- takeInt' rd n
	rd l

section' :: Monad m => (Int -> m BS.ByteString) -> Int -> ByteStringM a -> m a
section' rd n m = do
	l <- takeInt' rd n
	bs <- rd l
	let e = evalByteStringM m bs
	case e of
		Right x -> return x
		Left err -> error err

-- type FromByteString m a = (Int -> m BS.ByteString) -> m a

{-
-- section'' :: Monad m =>
--	(Int -> m BS.ByteString) -> Int -> FromByteString n a -> m a
section'' rd n m = do
	l <- takeInt' rd n
	bs <- rd l
	let e = evalByteStringM (m takeBS) bs
	case e of
		Right x -> return x
		Left err -> error err
		-}

section :: Int -> ByteStringM a -> ByteStringM a
section n m = do
	e <- evalByteStringM m <$> takeLen n
	case e of
		Right x -> return x
		Left err -> throwError err

whole :: ByteStringM ByteString
whole = do w <- get; put ""; return w

word16ToByteString :: Word16 -> ByteString
word16ToByteString w = BS.pack [fromIntegral (w `shiftR` 8), fromIntegral w]

word64ToByteString :: Word64 -> ByteString
word64ToByteString w64 = BS.replicate (8 - BS.length bs) 0 `BS.append` bs
	where
	bs = BS.reverse $ wtb w64
	wtb 0 = ""
	wtb w = fromIntegral (w .&. 0xff) `BS.cons` wtb (w `shiftR` 8)

byteStringToInt :: ByteString -> Int
byteStringToInt bs = wordsToInt (BS.length bs - 1) $ BS.unpack bs

wordsToInt :: Int -> [Word8] -> Int
wordsToInt n _ | n < 0 = 0
wordsToInt _ [] = 0
wordsToInt n (x : xs) = fromIntegral x `shift` (n * 8) .|. wordsToInt (n - 1) xs

intToByteString :: Int -> Int -> ByteString
intToByteString n = BS.pack . reverse . intToWords n

intToWords :: Int -> Int -> [Word8]
intToWords 0 _ = []
intToWords n i = fromIntegral i : intToWords (n - 1) (i `shiftR` 8)

lenBodyToByteString :: Int -> ByteString -> ByteString
lenBodyToByteString n bs = intToByteString n (BS.length bs) `BS.append` bs

instance Show Random where
	show (Random r) =
		"(Random " ++ concatMap (`showHex` "") (BS.unpack r) ++ ")"

instance Parsable Random where
	parse = parseRandom
	toByteString = randomToByteString
	listLength _ = Nothing

instance B.Bytable Random where
	fromByteString = Right . Random
	toByteString (Random bs) = bs

parseRandom :: ByteStringM Random
parseRandom = Random <$> takeBS 32

instance Parsable' Random where
	parse' rd = Random `liftM` rd 32
	toByteString' = randomToByteString

randomToByteString :: Random -> BS.ByteString
randomToByteString (Random r) = r

byteStringToCipherSuite :: BS.ByteString -> Either String CipherSuite
byteStringToCipherSuite bs = case BS.unpack bs of
	[w1, w2] -> Right $ case (w1, w2) of
		(0x00, 0x00) -> CipherSuite KeyExNULL MsgEncNULL
		(0x00, 0x2f) -> CipherSuite RSA AES_128_CBC_SHA
		(0x00, 0x33) -> CipherSuite DHE_RSA AES_128_CBC_SHA
		(0x00, 0x39) -> CipherSuite ECDHE_PSK NULL_SHA
		(0x00, 0x3c) -> CipherSuite RSA AES_128_CBC_SHA256
		(0x00, 0x45) -> CipherSuite DHE_RSA CAMELLIA_128_CBC_SHA
		(0x00, 0x67) -> CipherSuite DHE_RSA AES_128_CBC_SHA256
		(0xc0, 0x09) -> CipherSuite ECDHE_ECDSA AES_128_CBC_SHA
		(0xc0, 0x13) -> CipherSuite ECDHE_RSA AES_128_CBC_SHA
		(0xc0, 0x23) -> CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256
		(0xc0, 0x27) -> CipherSuite ECDHE_RSA AES_128_CBC_SHA256
		_ -> CipherSuiteRaw w1 w2
	_ -> Left "Types.byteStringToCipherSuite"

parseCipherSuite :: ByteStringM CipherSuite
parseCipherSuite = either error id . byteStringToCipherSuite <$> takeBS 2

parseCipherSuite' :: Monad m => (Int -> m BS.ByteString) -> m CipherSuite
parseCipherSuite' rd =
	(either error id . byteStringToCipherSuite) `liftM` takeLen' rd 2

instance B.Bytable CipherSuite where
	fromByteString = byteStringToCipherSuite
	toByteString = cipherSuiteToByteString

instance Parsable' CipherSuite where
	parse' = parseCipherSuite'
	toByteString' = cipherSuiteToByteString

instance Parsable CipherSuite where
	parse = parseCipherSuite
	toByteString = cipherSuiteToByteString
	listLength _ = Just 2

cipherSuiteToByteString :: CipherSuite -> BS.ByteString
cipherSuiteToByteString (CipherSuite KeyExNULL MsgEncNULL) = "\x00\x00"
cipherSuiteToByteString (CipherSuite RSA AES_128_CBC_SHA) = "\x00\x2f"
cipherSuiteToByteString (CipherSuite DHE_RSA AES_128_CBC_SHA) = "\x00\x33"
cipherSuiteToByteString (CipherSuite ECDHE_PSK NULL_SHA) = "\x00\x39"
cipherSuiteToByteString (CipherSuite RSA AES_128_CBC_SHA256) = "\x00\x3c"
cipherSuiteToByteString (CipherSuite DHE_RSA CAMELLIA_128_CBC_SHA) = "\x00\x45"
cipherSuiteToByteString (CipherSuite DHE_RSA AES_128_CBC_SHA256) = "\x00\x67"
cipherSuiteToByteString (CipherSuite ECDHE_ECDSA AES_128_CBC_SHA) = "\xc0\x09"
cipherSuiteToByteString (CipherSuite ECDHE_RSA AES_128_CBC_SHA) = "\xc0\x13"
cipherSuiteToByteString (CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256) = "\xc0\x23"
cipherSuiteToByteString (CipherSuite ECDHE_RSA AES_128_CBC_SHA256) = "\xc0\x27"
cipherSuiteToByteString (CipherSuiteRaw w1 w2) = BS.pack [w1, w2]
cipherSuiteToByteString _ = error "cannot identified"

instance Parsable' Version where
	parse' rd = do
		[vmjr, vmnr] <- takeWords' rd 2
		return $ Version vmjr vmnr
	toByteString' = versionToByteString

instance B.Bytable Version where
	fromByteString bs = case BS.unpack bs of
		[vmjr, vmnr] -> Right $ Version vmjr vmnr
		_ -> Left "Types.hs: B.Bytable Version"
	toByteString (Version vmjr vmnr) = BS.pack [vmjr, vmnr]
