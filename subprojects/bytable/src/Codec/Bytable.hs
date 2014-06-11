{-# LANGUAGE TupleSections #-}

module Codec.Bytable (BytableM(..), Bytable(..), head, take, null) where

import Prelude hiding (take, head, null)
import Control.Applicative(Applicative(..), (<$>))
import Control.Monad (unless, liftM, ap)
import Data.Word (Word8)
import qualified Data.ByteString as BS

data BytableM a = BytableM {
	runBytableM :: BS.ByteString -> Either String (a, BS.ByteString) }

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
	fromByteString :: BS.ByteString -> Either String b
	toByteString :: b -> BS.ByteString

head :: BytableM Word8
head = BytableM $ \bs -> case BS.uncons bs of
	Just (h, t) -> Right (h, t)
	_ -> Left "Bytable.head: null"

take :: Bytable b => Int -> BytableM b
take n = BytableM $ \bs -> do
	unless (BS.length bs >= n) .  Left $
		"Bytable.take: length shorter than " ++ show n
	let (x, bs') = BS.splitAt n bs
	(, bs') <$> fromByteString x

null :: BytableM Bool
null  = BytableM $ \bs -> Right (BS.null bs, bs)
