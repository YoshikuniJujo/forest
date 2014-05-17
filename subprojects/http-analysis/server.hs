import System.IO
import System.Environment
import Control.Concurrent
import Control.Applicative
import Control.Monad
-- import Data.List
import Data.Char
import Network

main :: IO ()
main = do
	pn : _ <- getArgs
	port <- PortNumber . fromIntegral <$> readIO pn
	socket <- listenOn port
	forever $ do
		(client, _, _) <- accept socket
		_ <- forkIO $ do
			h <- hGetHeader client
			print $ parse h
			hPutStrLn client answer
		return ()

hGetHeader :: Handle -> IO [String]
hGetHeader h = do
	l <- dropCR <$> hGetLine h
	if (null l ) then return [] else (l :) <$> hGetHeader h

dropCR :: String -> String
dropCR s = if last s == '\r' then init s else s

crlf :: [String] -> String
crlf = concatMap (++ "\r\n")

answer :: String
answer = crlf [
	"HTTP/1.1 200 OK",
	"Date: Wed, 07 May 2014 02:27:34 GMT",
	"Content-Length: 13",
	"Content-Type: text/plain",
	"",
	"Hello, world!"
 ]

data Request
	= Request Uri Version Get
	| RequestRaw RequestType Uri Version [(String, String)]
	deriving Show

data Get = Get {
	getHost :: Maybe Host,
	getUserAgent :: Maybe [Product],
	getAccept :: Maybe String,
	getAcceptLanguage :: Maybe String,
	getAcceptEncoding :: Maybe String,
	getConnection :: Maybe String,
	getCacheControl :: Maybe String,
	getOthers :: [(String, String)]
 } deriving Show

data RequestType
	= RequestTypeGet
	| RequestTypeRaw String
	deriving Show

data Uri = Uri String deriving Show

data Version = Version Int Int deriving Show

parse :: [String] -> Request
parse (h : t) = let
	(rt, uri, v) = parseRequestLine h in
	parseSep rt uri v $ map separate t
	where
	separate i = let (k, ':' : ' ' : v) = span (/= ':') i in (k, v)

parseSep :: RequestType -> Uri -> Version -> [(String, String)] -> Request
parseSep RequestTypeGet uri v kvs = Request uri v $ parseGet kvs
parseSep rt uri v kvs = RequestRaw rt uri v kvs

parseRequestLine :: String -> (RequestType, Uri, Version)
parseRequestLine rl = let
	[rts, uris, vs] = words rl
	rt = case rts of
		"GET" -> RequestTypeGet
		_ -> RequestTypeRaw rts in
	(rt, Uri uris, parseVersion vs)

parseVersion :: String -> Version
parseVersion ('H' : 'T' : 'T' : 'P' : '/' : vns) = let
	(vmjrs, '.' : vmnrs) = span (/= '.') vns in
	Version (read vmjrs) (read vmnrs)

parseGet :: [(String, String)] -> Get
parseGet kvs = Get {
	getHost = parseHost <$> lookup "Host" kvs,
	getUserAgent = map parseProduct . sepTkn <$> lookup "User-Agent" kvs,
	getAccept = lookup "Accept" kvs,
	getAcceptLanguage = lookup "Accept-Language" kvs,
	getAcceptEncoding = lookup "Accept-Encoding" kvs,
	getConnection = lookup "Connection" kvs,
	getCacheControl = lookup "Cache-Control" kvs,
	getOthers = filter ((`notElem` getKeys) . fst) kvs
 }

sepTkn :: String -> [String]
sepTkn "" = []
sepTkn ('(' : src) = ('(' : cm ++ ")") : sepTkn (dropWhile isSpace src')
	where
	(cm, ')' : src') = span (/= ')') src
sepTkn src = tk : sepTkn (dropWhile isSpace src')
	where
	(tk, src') = span (not . isSpace) src

getKeys :: [String]
getKeys = [
	"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
	"Connection", "Cache-Control"
 ]

data Host = Host String (Maybe Int) deriving Show

parseHost :: String -> Host
parseHost src = case span (/= ':') src of
	(h, ':' : p) -> Host h (Just $ read p)
	(h, _) -> Host h Nothing

data Product
	= Product String (Maybe String)
	| ProductComment String
	deriving Show

parseProduct :: String -> Product
parseProduct ('(' : cm) = case last cm of
	')' -> ProductComment $ init cm
	_ -> error "parseProduct: bad comment"
parseProduct pnv = case span (/= '/') pnv of
	(pn, '/' : v) -> Product pn $ Just v
	_ -> Product pnv Nothing
