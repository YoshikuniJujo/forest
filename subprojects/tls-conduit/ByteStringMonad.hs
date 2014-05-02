{-# LANGUAGE PackageImports, OverloadedStrings #-}

module ByteStringMonad (
	ByteString, Word8, BS.pack, BS.unpack, BS.append, BS.concat,

	ByteStringM, evalByteStringM, throwError,
	head, take, takeWords, takeInt, takeLen, empty,
	list1, list, section, whole
) where

import Prelude hiding (head, take)

import Control.Applicative ((<$>), (<*>))

import Data.Word
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error

import Tools

type ByteStringM = ErrorT String (State ByteString)

evalByteStringM :: ByteStringM a -> ByteString -> Either String a
evalByteStringM m bs = case runState (runErrorT m) bs of
	(Right x, "") -> Right x
	(Right _, rest) -> Left $ "rest: " ++ show rest
	(err, _) -> err

head :: ByteStringM Word8
head = do
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

takeLen :: Int -> ByteStringM ByteString
takeLen n = do
	len <- takeInt n
	take len

empty :: ByteStringM Bool
empty = (== BS.empty) <$> get

list1 :: ByteStringM a -> ByteStringM [a]
list1 m = do
	x <- m
	e <- empty
	if e then return [x] else (x :) <$> list1 m

list :: ByteStringM a -> ByteStringM [a]
list m = do
	e <- empty
	if e then return [] else (:) <$> m <*> list m

section :: Int -> ByteStringM a -> ByteStringM a
section n m = do
	e <- evalByteStringM m <$> takeLen n
	case e of
		Right x -> return x
		Left err -> throwError err

whole :: ByteStringM ByteString
whole = do w <- get; put ""; return w
