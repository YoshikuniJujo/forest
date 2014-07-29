{-# LANGUAGE OverloadedStrings, TypeFamilies, QuasiQuotes #-}

module Papillon (parseAtts) where

import Text.Papillon
import Data.ByteString.Char8 (ByteString, pack)

import qualified Data.ByteString as BS
-- import qualified Data.ByteString.Char8 as BSC

parseAtts :: BS.ByteString -> Maybe [(BS.ByteString, BS.ByteString)]
parseAtts = either (const Nothing) (Just . fst) . runError . atts . parse

isTextChar :: Char -> Bool
isTextChar = (`elem` (['0' .. '9'] ++ ['a' .. 'z'] ++ ['A' .. 'Z'] ++ "-"))

[papillon|

source: ByteString

atts :: [(ByteString, ByteString)]
	= a:att ',' as:atts		{ a : as }
	/ a:att				{ [a] }

att :: (ByteString, ByteString)
	= k:(<(`notElem` "=")>)+ '=' v:txt	{ (pack k, v) }

txt :: ByteString
	= '"' t:(<(`notElem` "\"")>)* '"'	{ pack t }
	/ t:(<isTextChar>)+			{ pack t }

|]

{-
instance Source ByteString where
	type Token ByteString = Char
	data Pos ByteString = NoPos
	getToken = BSC.uncons
	initialPos = NoPos
	updatePos _ _ = NoPos
	-}
