{-# LANGUAGE PackageImports, OverloadedStrings, ScopedTypeVariables #-}

module ByteStringMonad (
	ByteString, Word8, Word16, BS.pack, BS.unpack, BS.append, BS.concat,

	ByteStringM, evalByteStringM, throwError,
	headBS, take, takeWords, takeInt, takeWord16, takeLen, emptyBS,
	list1, list, section, whole,

	word16ToByteString,

	byteStringToInt, intToByteString, lenBodyToByteString,

	Parsable(..),
) where

import Prelude hiding (head, take)
import qualified Prelude

import Control.Applicative ((<$>), (<*>))

import Data.Bits
import Data.Word
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error

-- import Tools
import Tools

class Parsable a where
	parse :: ByteStringM a
	toByteString :: a -> ByteString
	listLength :: a -> Maybe Int

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

take :: Int -> ByteStringM ByteString
take len = do
	(t, d) <- lift $ gets (BS.splitAt len)
	if BS.length t /= len
	then throwError $ "ByteStringMonad.take:\n" ++
		"expected: " ++ show len ++ "bytes\n" ++
		"actual  : " ++ show (BS.length t) ++ "bytes\n"
	else do
		lift $ put d
		return t

takeWords :: Int -> ByteStringM [Word8]
takeWords = (BS.unpack <$>) . take

takeInt :: Int -> ByteStringM Int
takeInt = (byteStringToInt <$>) . take

takeWord16 :: ByteStringM Word16
takeWord16 = do
	[w1, w2] <- takeWords 2
	return $ fromIntegral w1 `shift` 8 .|. fromIntegral w2

takeLen :: Int -> ByteStringM ByteString
takeLen n = do
	len <- takeInt n
	take len

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

{-
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
-}
