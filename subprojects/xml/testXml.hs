{-# LANGUAGE TypeFamilies, QuasiQuotes, OverloadedStrings, PackageImports #-}

import System.IO
import Control.Arrow
import Text.Papillon
import Data.Char
import "monads-tf" Control.Monad.State

type TagIO = StateT ([Xml], [(Name, Attrs)]) IO

readHandle :: Handle -> TagIO [Xml]
readHandle h = do
	c <- liftIO $ hGetChar h
	case c of
		'<' -> do
			readHandleTag h
		_ -> error "not implemented"

readHandleTail :: Handle -> TagIO [Xml]
readHandleTail h = do
--	get >>= liftIO . print
	tgs <- gets snd
	ret <- if null tgs then return [] else do
		c <- liftIO $ hGetChar h
		case c of
			'<' -> readHandleTag h
			_ -> do	tx <- readUntil (== '<') h
				(++) <$> readString (c : init tx)
					<*> readHandleTag h
--	liftIO $ print ret
	return ret
				

readHandleTag :: Handle -> TagIO [Xml]
readHandleTag h = do
--	get >>= liftIO . print
--	liftIO $ hGetChar h >>= print
	tg <- readUntil (== '>') h
	(++) <$> readString ('<' : tg) <*> readHandleTail h

readUntil :: (Char -> Bool) -> Handle -> TagIO String
readUntil p h = do
	c <- liftIO $ hGetChar h
	if p c then return [c] else (c :) <$> readUntil p h

readString :: String -> TagIO [Xml]
readString "" = gets $ reverse . fst
readString tg@('<' : _) = case readTag tg of
	Just (OpenTag n as) -> do
		modify $ second ((n, as) :)
		readString (tail $ dropWhile (/= '>') tg)
	Just (CloseTag cn) -> do
		ts@((n, as) : _) <- gets snd
		let m = case ts of
			(on, _) : _ -> cn == on
			_ -> False
		if not m then error "tag not match" else do
			xmls <- gets fst
			modify . first $ const []
			modify $ second tail
			(Node n as (reverse xmls) :) <$>
				readString (tail $ dropWhile (/= '>') tg)
	_ -> error $ "bad tag: " ++ tg
readString strtg = do
	modify $ first (Text str :)
	readString tg
	where
	(str, tg) = span (/= '<') strtg

type Name = (Maybe String, String)
type Attrs = [((Maybe String, String), String)]

data Xml = Node Name Attrs [Xml] | Text String deriving Show

data Tag = OpenTag Name Attrs | CloseTag Name deriving Show

match :: Tag -> Tag -> Bool
match (OpenTag otn _) (CloseTag ctn) = otn == ctn
match _ _ = False

readTag :: String -> Maybe Tag
readTag src = case runError $ tag $ parse src of
	Right (t, _) -> Just t
	_ -> Nothing

{-
testAttr :: String -> Maybe (String, String)
testAttr src = case runError $ attr $ parse src of
	Right (t, _) -> Just t
	_ -> Nothing
	-}

testString :: String -> Maybe String
testString src = case runError $ string $ parse src of
	Right (t, _) -> Just t
	_ -> Nothing

[papillon|

tag :: Tag = ot:openTag { ot } / ct:closeTag { ct }

openTag :: Tag
	= '<' _:spaces n:name _:spaces as:attrs '>'
		{ OpenTag n as }

closeTag :: Tag
	= '<' '/' _:spaces n:name '>'
		{ CloseTag n }

name :: (Maybe String, String)
	= qn:(n:<isAlpha>+ ':' { n })? n:<isAlpha>+
						{ (qn, n) }

attrs :: [((Maybe String, String), String)]
	= a:attr _:spaces as:attrs		{ a : as }
	/					{ [] }

attr :: ((Maybe String, String), String) = n:name '=' s:string	{ (n, s) }

string :: String
	= '"' s:<(/= '"')>* '"'			{ s }
	/ '\'' s:<(/= '\'')>* '\''		{ s }

spaces :: () = _:<isSpace>*

|]
