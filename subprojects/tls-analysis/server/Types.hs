{-# LANGUAGE OverloadedStrings, PackageImports, ScopedTypeVariables #-}

module Types (
	Version(..), byteStringToVersion, versionToByteString,
	ContentType(..), byteStringToContentType, contentTypeToByteString,
	Random(..), CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),

	NamedCurve(..),

	SignatureAlgorithm(..),
	HashAlgorithm(..),
	Parsable(..),
	Parsable'(..),

	lenBodyToByteString, Word8, headBS,

	word16ToByteString,
	word64ToByteString,

	intToByteString,
	byteStringToInt,
	takeLen,
	evalByteStringM,

	takeWords, takeWords',
	takeBS,
	ByteStringM,
	takeLen',
	section,
	emptyBS,
	whole,

	namedCurveToByteString,
	list,
	list1,
	parseNamedCurve,
	section',
	throwError,
) where

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

instance Parsable NamedCurve where
	parse = parseNamedCurve
	toByteString = namedCurveToByteString
	listLength _ = Nothing

parseNamedCurve :: ByteStringM NamedCurve
parseNamedCurve = do
	nc <- takeWord16
	return $ case nc of
		23 -> Secp256r1
		24 -> Secp384r1
		25 -> Secp521r1
		_ -> NamedCurveRaw nc

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

instance Parsable a => Parsable [a] where
	parse = case listLength (undefined :: a) of
		Just n -> section n $ list parse
		_ -> list parse
	toByteString = case listLength (undefined :: a) of
		Just n -> lenBodyToByteString n . BS.concat . map toByteString
		_ -> error "Parsable [a]: Not set list len"
	listLength _ = Nothing

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

takeWord16 :: ByteStringM Word16
takeWord16 = do
	[w1, w2] <- takeWords 2
	return $ fromIntegral w1 `shift` 8 .|. fromIntegral w2

takeLen :: Int -> ByteStringM ByteString
takeLen n = do
	len <- takeInt n
	takeBS len

takeLen' :: Monad m => (Int -> m BS.ByteString) -> Int -> m BS.ByteString
takeLen' rd n = do
	len <- takeInt' rd n
	rd len

emptyBS :: ByteStringM Bool
emptyBS = (== BS.empty) <$> get

list1 :: ByteStringM a -> ByteStringM [a]
list1 m = do
	x <- m
	e <- emptyBS
	if e then return [x] else (x :) <$> list1 m

list :: ByteStringM a -> ByteStringM [a]
list m = do
	e <- emptyBS
	if e then return [] else (:) <$> m <*> list m

{-
list' :: Monad m => (Int -> m BS.ByteString) ->
	((Int -> m BS.ByteString) -> m a) -> m [a]
list' rd m = do
	e <- empty
	-}

section' :: Monad m => (Int -> m BS.ByteString) -> Int -> ByteStringM a -> m a
section' rd n m = do
	l <- takeInt' rd n
	bs <- rd l
	let e = evalByteStringM m bs
	case e of
		Right x -> return x
		Left err -> error err

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
