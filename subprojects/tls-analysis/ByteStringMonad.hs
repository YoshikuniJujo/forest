{-# LANGUAGE PackageImports, OverloadedStrings #-}

module ByteStringMonad (
	ByteString, Word8, Word16, BS.pack, BS.unpack, BS.append, BS.concat,

	ByteStringM, evalByteStringM, throwError,
	headBS, take, takeWords, takeInt, takeWord16, takeLen, emptyBS,
	list1, list, section, whole,

	lenBodyToByteString, word16ToByteString, word64ToByteString,

	fst3, fromInt,

	byteStringToInt, intToByteString, showKeySingle, showKey,
) where

import Prelude hiding (head, take)
import qualified Prelude

import Numeric
import Control.Applicative ((<$>), (<*>))

import Data.Bits
import Data.Word
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error

-- import Tools

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
	if BS.length t /= len then throwError "ByteStringMonad.take" else do
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

lenBodyToByteString :: Int -> ByteString -> ByteString
lenBodyToByteString n bs = intToByteString n (BS.length bs) `BS.append` bs

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

showKeySingle :: ByteString -> String
showKeySingle = unwords . map showH . BS.unpack

showKey :: ByteString -> String
showKey = unlines . map (('\t' :) . unwords) . separateN 16 . map showH . BS.unpack
	where
	separateN _ [] = []
	separateN n xs = Prelude.take n xs : separateN n (drop n xs)

showH :: Word8 -> String
showH w = let s = showHex w "" in replicate (2 - length s) '0' ++ s

fromInt :: Integral i => Int -> i
fromInt = fromIntegral

fst3 :: (a, b, c) -> a
fst3 (x, _, _) = x
