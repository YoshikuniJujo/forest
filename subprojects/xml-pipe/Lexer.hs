{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Lexer (sepTag) where

-- import "monads-tf" Control.Monad.Trans
import Data.Pipe
-- import Data.Pipe.List
-- import Data.Word8
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

endWith :: Monad m =>
	(Char -> Bool) -> Char -> BS.ByteString -> Pipe BS.ByteString BS.ByteString m ()
endWith p c rest = do
	let (t, d) = BSC.span (not . p) rest
	if BS.null d
	then do	mbs <- await
		case mbs of
			Just bs -> endWith p c $ t `BS.append` bs
			_ -> return ()
	else yield (BSC.cons c t) >> endWith p (BSC.head d) (BS.tail d)

-- endByDot :: Monad m => Pipe BS.ByteString BS.ByteString m ()
-- -- -- -- -- -- -- -- endByDot = endWith (== '.') '.' ""

sepTag :: Monad m => Pipe BS.ByteString BS.ByteString m ()
sepTag = endWith (`elem` "<>") '>' ""

{-
endByDot :: Monad m => BS.ByteString -> Pipe BS.ByteString BS.ByteString m ()
endByDot rest = do
	let (t, d) = BS.span (/= 46) rest
	if BS.null d
	then do	mbs <- await
		case mbs of
			Just bs -> endByDot $ t `BS.append` bs
			_ -> return ()
	else yield t >> endByDot (BS.tail d)
	-}

{-
bsToUpper :: BS.ByteString -> BS.ByteString
bsToUpper = BS.pack . map toUpper . BS.unpack

upper :: Monad m => Pipe BS.ByteString BS.ByteString m ()
upper = await >>= maybe (return ()) (\bs -> yield (bsToUpper bs) >> upper)
-}
