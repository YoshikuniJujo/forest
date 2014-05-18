import System.IO
import System.Environment
import Control.Concurrent
import Control.Applicative
import Control.Monad
import Data.Maybe
import Data.List
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
			mapM putStrLn h
			putStrLn ""
			print $ parse h
			putStrLn ""
			mapM putStrLn . catMaybes . showRequest $ parse h
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
	= RequestGet Uri Version Get
	| RequestRaw RequestType Uri Version [(String, String)]
	deriving Show

showRequest :: Request -> [Maybe String]
showRequest (RequestGet uri vsn g) = [
	Just $ "GET " ++ showUri uri ++ " HTTP/" ++ showVersion vsn,
	("Host: " ++) . showHost <$> getHost g,
	("User-Agent: " ++) . unwords . map showProduct <$> getUserAgent g,
	("Accept: " ++) . intercalate "," . map showAccept <$> getAccept g
 ]

data Get = Get {
	getHost :: Maybe Host,
	getUserAgent :: Maybe [Product],
	getAccept :: Maybe [Accept],
	getAcceptLanguage :: Maybe [AcceptLanguage],
	getAcceptEncoding :: Maybe [AcceptEncoding],
	getConnection :: Maybe [Connection],
	getCacheControl :: Maybe [CacheControl],
	getOthers :: [(String, String)]
 } deriving Show

data RequestType
	= RequestTypeGet
	| RequestTypeRaw String
	deriving Show

data Uri = Uri String deriving Show

showUri :: Uri -> String
showUri (Uri uri) = uri

data Version = Version Int Int deriving Show

showVersion :: Version -> String
showVersion (Version vmjr vmnr) = show vmjr ++ "." ++ show vmnr

parse :: [String] -> Request
parse (h : t) = let
	(rt, uri, v) = parseRequestLine h in
	parseSep rt uri v $ map separate t
	where
	separate i = let (k, ':' : ' ' : v) = span (/= ':') i in (k, v)

parseSep :: RequestType -> Uri -> Version -> [(String, String)] -> Request
parseSep RequestTypeGet uri v kvs = RequestGet uri v $ parseGet kvs
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
	getAccept = map parseAccept . unlist <$> lookup "Accept" kvs,
	getAcceptLanguage =
		map parseAcceptLanguage . unlist <$> lookup "Accept-Language" kvs,
	getAcceptEncoding =
		map parseAcceptEncoding . unlist <$> lookup "Accept-Encoding" kvs,
	getConnection = map parseConnection . unlist <$> lookup "Connection" kvs,
	getCacheControl =
		map parseCacheControl . unlist <$> lookup "Cache-Control" kvs,
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

showHost :: Host -> String
showHost (Host h p) = h ++ (maybe "" ((':' :) . show) p)

data Product
	= Product String (Maybe String)
	| ProductComment String
	deriving Show

showProduct :: Product -> String
showProduct (Product pn mpv) = pn ++ case mpv of
	Just v -> '/' : v
	_ -> ""
showProduct (ProductComment cm) = "(" ++ cm ++ ")"

parseProduct :: String -> Product
parseProduct ('(' : cm) = case last cm of
	')' -> ProductComment $ init cm
	_ -> error "parseProduct: bad comment"
parseProduct pnv = case span (/= '/') pnv of
	(pn, '/' : v) -> Product pn $ Just v
	_ -> Product pnv Nothing

data Accept
	= Accept (String, String) Qvalue
	deriving Show

showAccept :: Accept -> String
showAccept (Accept (t, st) qv) = ((t ++ "/" ++ st) ++) $ case showQvalue qv of
	"" -> ""
	s -> ';' : s

parseAccept :: String -> Accept
parseAccept src = case span (/= ';') src of
	(mr, ';' : qv) -> Accept (parseMediaRange mr) $ parseQvalue qv
	(mr, "") -> Accept (parseMediaRange mr) $ Qvalue 1

parseMediaRange :: String -> (String, String)
parseMediaRange src = case span (/= '/') src of
	(t, '/' : st) -> (t, st)
	_ -> error "parseMediaRange: bad media range"

unlist :: String -> [String]
unlist "" = []
unlist src = case span (/= ',') src of
	(h, ',' : t) -> h : unlist (dropWhile isSpace t)
	(h, "") -> [h]

data Qvalue
	= Qvalue Double
	deriving Show

showQvalue :: Qvalue -> String
showQvalue (Qvalue 1.0) = ""
showQvalue (Qvalue qv) = "q=" ++ show qv

parseQvalue :: String -> Qvalue
parseQvalue ('q' : '=' : qv) = Qvalue $ read qv

data AcceptLanguage
	= AcceptLanguage String Qvalue
	deriving Show

parseAcceptLanguage :: String -> AcceptLanguage
parseAcceptLanguage src = case span (/= ';') src of
	(al, ';' : qv) -> AcceptLanguage al $ parseQvalue qv
	(al, "") -> AcceptLanguage al $ Qvalue 1

data AcceptEncoding
	= AcceptEncoding String Qvalue
	deriving Show

parseAcceptEncoding :: String -> AcceptEncoding
parseAcceptEncoding src = case span (/= ';') src of
	(ae, ';' : qv) -> AcceptEncoding ae $ parseQvalue qv
	(ae, "") -> AcceptEncoding ae $ Qvalue 1

data Connection
	= Connection String
	deriving Show

parseConnection :: String -> Connection
parseConnection src = Connection src

data CacheControl
	= MaxAge Int
	| CacheControlRaw String
	deriving Show

parseCacheControl :: String -> CacheControl
parseCacheControl ('m' : 'a' : 'x' : '-' : 'a' : 'g' : 'e' : '=' : ma) =
	MaxAge $ read ma
