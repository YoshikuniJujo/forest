{-# LANGUAGE OverloadedStrings, TypeFamilies, QuasiQuotes #-}

import Data.Char
import Data.ByteString (ByteString)
import Text.Papillon

import qualified Data.ByteString.Char8 as BSC

parseXmlDecl :: ByteString -> Maybe (Int, Int)
parseXmlDecl = either (const Nothing) (Just . fst) . runError . xmlDecl . parse

[papillon|

source: ByteString

xmlDecl :: (Int, Int)
	= '<' '?' 'x' 'm' 'l' vi:versionInfo _:spaces? '?' '>'
	{ vi }

versionInfo :: (Int, Int)
	= _:spaces 'v' 'e' 'r' 's' 'i' 'o' 'n' _:eq
		'"' v:versionNum '"'
	{ v }

eq :: () = _:spaces? '=' _:spaces?

versionNum :: (Int, Int)
	= '1' '.' d:<isDigit>+			{ (1, read d) }

spaces :: () = _:(' ' / '\t' / '\r' / '\n')+

|]

instance Source ByteString where
	type Token ByteString = Char
	data Pos ByteString = NoPos
	getToken = BSC.uncons
	initialPos = NoPos
	updatePos _ _ = NoPos
