{-# LANGUAGE PatternGuards, OverloadedStrings, TupleSections #-}

module Codec.Bytable (
	Bytable(..), fromByteString, toByteString,
	Parsable(..),
	BytableM(..), evalBytableM, execBytableM,
	head, take, null, list, addLen,
) where

import Prelude hiding (take, head, null)
import Control.Applicative(Applicative(..), (<$>))
import Control.Monad (unless, liftM, ap)
import Data.Word (Word8)
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

fromByteString :: Bytable b => BS.ByteString -> Either String b
fromByteString = decode

toByteString :: Bytable b => b -> BS.ByteString
toByteString = encode

{-# DEPRECATED fromByteString "Use decode instead" #-}
{-# DEPRECATED toByteString "Use encode instead" #-}

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
