import Control.Concurrent
import Control.Applicative
import Control.Monad
import Data.Maybe
import Data.List
import Data.Char
import Data.Time
import System.IO
import System.Environment
import System.Locale
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
			hPutStrLn client answer'
		return ()

hGetHeader :: Handle -> IO [String]
hGetHeader h = do
	l <- dropCR <$> hGetLine h
	if (null l ) then return [] else (l :) <$> hGetHeader h

dropCR :: String -> String
dropCR s = if last s == '\r' then init s else s

crlf :: [String] -> String
crlf = concatMap (++ "\r\n")

data Request
	= RequestGet Uri Version Get
	| RequestRaw RequestType Uri Version [(String, String)]
	deriving Show

showRequest :: Request -> [Maybe String]
showRequest (RequestGet uri vsn g) = [
	Just $ "GET " ++ showUri uri ++ " " ++ showVersion vsn,
	("Host: " ++) . showHost <$> getHost g,
	("User-Agent: " ++) . unwords . map showProduct <$> getUserAgent g,
	("Accept: " ++) . intercalate "," . map showAccept <$> getAccept g,
	("Accept-Language: " ++) . intercalate "," .
		map showAcceptLanguage <$> getAcceptLanguage g,
	("Accept-Encoding: " ++) . intercalate "," .
		map showAcceptEncoding <$> getAcceptEncoding g,
	("Connection: " ++) . intercalate "," .
		map showConnection <$> getConnection g,
	("Cache-Control: " ++) . intercalate "," .
		map showCacheControl <$> getCacheControl g
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
showVersion (Version vmjr vmnr) = "HTTP/" ++ show vmjr ++ "." ++ show vmnr

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
showAccept (Accept (t, st) qv) = ((t ++ "/" ++ st) ++) $ showQvalue qv

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
showQvalue (Qvalue qv) = ";q=" ++ show qv

parseQvalue :: String -> Qvalue
parseQvalue ('q' : '=' : qv) = Qvalue $ read qv

data AcceptLanguage
	= AcceptLanguage String Qvalue
	deriving Show

showAcceptLanguage :: AcceptLanguage -> String
showAcceptLanguage (AcceptLanguage al qv) = al ++ showQvalue qv

parseAcceptLanguage :: String -> AcceptLanguage
parseAcceptLanguage src = case span (/= ';') src of
	(al, ';' : qv) -> AcceptLanguage al $ parseQvalue qv
	(al, "") -> AcceptLanguage al $ Qvalue 1

data AcceptEncoding
	= AcceptEncoding String Qvalue
	deriving Show

showAcceptEncoding :: AcceptEncoding -> String
showAcceptEncoding (AcceptEncoding ae qv) = ae ++ showQvalue qv

parseAcceptEncoding :: String -> AcceptEncoding
parseAcceptEncoding src = case span (/= ';') src of
	(ae, ';' : qv) -> AcceptEncoding ae $ parseQvalue qv
	(ae, "") -> AcceptEncoding ae $ Qvalue 1

data Connection
	= Connection String
	deriving Show

showConnection :: Connection -> String
showConnection (Connection c) = c

parseConnection :: String -> Connection
parseConnection src = Connection src

data CacheControl
	= MaxAge Int
	| CacheControlRaw String
	deriving Show

showCacheControl :: CacheControl -> String
showCacheControl (MaxAge ma) = "max-age=" ++ show ma
showCacheControl (CacheControlRaw cc) = cc

parseCacheControl :: String -> CacheControl
parseCacheControl ('m' : 'a' : 'x' : '-' : 'a' : 'g' : 'e' : '=' : ma) =
	MaxAge $ read ma
parseCacheControl cc = CacheControlRaw cc

answer :: String
answer = crlf [
	"HTTP/1.1 200 OK",
	"Date: Wed, 07 May 2014 02:27:34 GMT",
	"Content-Length: 13",
	"Content-Type: text/plain",
	"",
	"Hello, world!"
 ]

answer' :: String
answer' = crlf . showResponse $ Response {
	responseVersion = Version 1 1,
	responseStatusCode = OK,
	responseDate = readTime defaultTimeLocale
		"%a, %d %b %Y %H:%M:%S" "Wed, 07 May 2014 02:27:34",
	responseContentLength = ContentLength 13,
	responseContentType = ContentType ("text", "plain"),
	responseOthers = [],
	responseBody = "Hello, world!"
 }

data Response = Response {
	responseVersion :: Version,
	responseStatusCode :: StatusCode,
	responseDate :: UTCTime,
	responseContentLength :: ContentLength,
	responseContentType :: ContentType,
	responseOthers :: [(String, String)],
	responseBody :: String
 }

showResponse :: Response -> [String]
showResponse r =
	[	showVersion (responseVersion r) ++ " " ++
			showStatusCode (responseStatusCode r),
		"Date: " ++ showTime (responseDate r),
		"Content-Length: " ++
			showContentLength (responseContentLength r),
		"Content-Type: " ++
			showContentType (responseContentType r)
	 ] ++
	map (\(k, v) -> k ++ ": " ++ v) (responseOthers r) ++
	[	"",
		responseBody r
	 ]

data StatusCode = Continue | SwitchingProtocols | OK deriving Show

showStatusCode :: StatusCode -> String
showStatusCode Continue = "100 Continue"
showStatusCode SwitchingProtocols = "101 SwitchingProtocols"
showStatusCode OK = "200 OK"

data ContentLength = ContentLength Int deriving Show

showContentLength :: ContentLength -> String
showContentLength (ContentLength n) = show n

data ContentType = ContentType (String, String) deriving Show

showContentType :: ContentType -> String
showContentType (ContentType (t, st)) = t ++ "/" ++ st

showTime :: UTCTime -> String
showTime = formatTime defaultTimeLocale "%a, %d %b %Y %H:%M:%S GMT"
