{-# LANGUAGE PatternGuards, OverloadedStrings, TupleSections #-}

module Codec.Bytable.BigEndian (
	Bytable(..), Parsable(..),
	BytableM(..), evalBytableM, execBytableM,
	head, take, null, list, addLen,
) where

import Prelude hiding (take, head, null)
import Control.Applicative(Applicative(..), (<$>))
import Control.Monad (unless, liftM, ap)
import Data.Bits (Bits, shiftL, shiftR, (.|.))
import Data.Word (Word8, Word16, Word32, Word64)
import Data.Word.Word24 (Word24)
import qualified Data.ByteString as BS

data BytableM a = BytableM {
	runBytableM :: BS.ByteString -> Either String (a, BS.ByteString) }

evalBytableM :: BytableM a -> BS.ByteString -> Either String a
evalBytableM m bs = fst <$> runBytableM m bs

execBytableM :: BytableM a -> BS.ByteString -> Either String BS.ByteString
execBytableM m bs = snd <$> runBytableM m bs

instance Monad BytableM where
	return x = BytableM $ \bs -> Right (x, bs)
	BytableM m1 >>= f = BytableM $ \bs -> do
		(x, bs') <- m1 bs
		runBytableM (f x) bs'
	fail = BytableM . const . Left

instance Functor BytableM where
	fmap = liftM

instance Applicative BytableM where
	pure = return
	(<*>) = ap

class Bytable b where
	decode :: BS.ByteString -> Either String b
	encode :: b -> BS.ByteString

instance Bytable Word8 where
	decode "" = Right 0
	decode bs
		| [w] <- BS.unpack bs = Right w
	decode _ = Left "Codec.Bytable.BigEndian: Bytable Word8: too large"
	encode = BS.pack . (: [])

instance Bytable BS.ByteString where
	decode = Right
	encode = id

class Parsable p where
	parse :: BytableM p

head :: BytableM Word8
head = BytableM $ \bs -> case BS.uncons bs of
	Just (h, t) -> Right (h, t)
	_ -> Left "Bytable.head: null"

take :: Bytable b => Int -> BytableM b
take n = BytableM $ \bs -> do
	unless (BS.length bs >= n) .  Left $
		"Bytable.take: length shorter than " ++ show n
	let (x, bs') = BS.splitAt n bs
	(, bs') <$> decode x

null :: BytableM Bool
null  = BytableM $ \bs -> Right (BS.null bs, bs)

list :: Int -> BytableM b -> BytableM [b]
list n m = do
	bs <- take n
	case evalBytableM lst bs of
		Right xs -> return xs
		Left msg -> fail msg
	where
	lst = do
		e <- null
		if e then return [] else (:) <$> m <*> lst

addLen :: (Bytable n, Num n) => n -> BS.ByteString -> BS.ByteString
addLen t bs =
	encode (fromIntegral (BS.length bs) `asTypeOf` t) `BS.append` bs

instance Bytable Int where
	decode bs
		| BS.length bs <= 4 = Right $ byteStringToNum bs
		| otherwise = Left
			"Codec.Bytable.BigEndian: Bytable Int: too large"
	encode = integralToByteStringN 4

instance Bytable Integer where
	decode bs = Right $ byteStringToNum bs
	encode = integralToByteString

instance Bytable Word16 where
	decode bs
		| BS.length bs <= 2 = Right $ byteStringToNum bs
		| otherwise = Left
			"Codec.Bytable.BigEndian: Bytable Word16: too large"
	encode = integralToByteStringN 2

instance Bytable Word24 where
	decode bs
		| BS.length bs <= 3 = Right $ byteStringToNum bs
		| otherwise = Left
			"Codec.Bytable.BigEndian: Bytable Word24: too large"
	encode = integralToByteStringN 3

instance Bytable Word32 where
	decode bs
		| BS.length bs <= 4 = Right $ byteStringToNum bs
		| otherwise = Left
			"Codec.Bytable.BigEndian: Bytable Word32: too large"
	encode = integralToByteStringN 4

instance Bytable Word64 where
	decode bs
		| BS.length bs <= 8 = Right $ byteStringToNum bs
		| otherwise = Left
			"Codec.Bytable.BigEndian: Bytable Word32: too large"
	encode = integralToByteStringN 8

byteStringToNum :: (Num n, Bits n) => BS.ByteString -> n
byteStringToNum = wordsToNum . reverse . BS.unpack

wordsToNum :: (Num n, Bits n) => [Word8] -> n
wordsToNum [] = 0
wordsToNum (w : ws) = fromIntegral w .|. wordsToNum ws `shiftL` 8

integralToByteString :: (Integral n, Bits n) => n -> BS.ByteString
integralToByteString = BS.pack . reverse . integralToWords

integralToByteStringN :: (Integral n, Bits n) => Int -> n -> BS.ByteString
integralToByteStringN n = BS.pack .
	(\ws -> replicate (n - length ws) 0 ++ ws) .
	reverse . integralToWords

integralToWords :: (Integral n, Bits n) => n -> [Word8]
integralToWords 0 = []
integralToWords n = fromIntegral n : integralToWords (n `shiftR` 8)
