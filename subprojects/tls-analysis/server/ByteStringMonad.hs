{-# LANGUAGE PackageImports, OverloadedStrings, ScopedTypeVariables #-}

module ByteStringMonad (
	ByteString, Word8, Word16, BS.pack, BS.unpack, BS.append, BS.concat,

	ByteStringM, evalByteStringM, throwError,
	headBS, takeBS, takeWords, takeInt, takeWord16, takeLen, emptyBS,
	list1, list, section', section, whole,

	takeWords', takeLen',

	word16ToByteString,

	byteStringToInt, intToByteString, lenBodyToByteString,

	Parsable(..), Parsable'(..),
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
