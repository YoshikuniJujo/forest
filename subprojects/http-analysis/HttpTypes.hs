module HttpTypes (
	Version(..),
	Request(..), RequestType(..), Uri(..), Get(..), CacheControl(..),
	Accept(..), AcceptLanguage(..), Qvalue(..),
	Host(..), Product(..), Connection(..),
	Response(..), StatusCode(..), ContentLength(..), ContentType(..),

	parse, parseResponse, showRequest, showResponse
) where

import Control.Applicative
import Data.Maybe
import Data.List
import Data.Char
import Data.Time
import System.Locale

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
		map showCacheControl <$> getCacheControl g,
	Just ""
 ]
showRequest (RequestRaw _ _ _ _) = error "showRequest: not implemented"

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
parse [] = error "parse: bad request"

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
parseVersion _ = error "parseVersion: bad http version"

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
	_ -> error "parseAccept: never occur"

parseMediaRange :: String -> (String, String)
parseMediaRange src = case span (/= '/') src of
	(t, '/' : st) -> (t, st)
	_ -> error "parseMediaRange: bad media range"

unlist :: String -> [String]
unlist "" = []
unlist src = case span (/= ',') src of
	(h, ',' : t) -> h : unlist (dropWhile isSpace t)
	(h, "") -> [h]
	_ -> error "unlist: never occur"

data Qvalue
	= Qvalue Double
	deriving Show

showQvalue :: Qvalue -> String
showQvalue (Qvalue 1.0) = ""
showQvalue (Qvalue qv) = ";q=" ++ show qv

parseQvalue :: String -> Qvalue
parseQvalue ('q' : '=' : qv) = Qvalue $ read qv
parseQvalue _ = error "parseQvalue: bad qvalue"

data AcceptLanguage
	= AcceptLanguage String Qvalue
	deriving Show

showAcceptLanguage :: AcceptLanguage -> String
showAcceptLanguage (AcceptLanguage al qv) = al ++ showQvalue qv

parseAcceptLanguage :: String -> AcceptLanguage
parseAcceptLanguage src = case span (/= ';') src of
	(al, ';' : qv) -> AcceptLanguage al $ parseQvalue qv
	(al, "") -> AcceptLanguage al $ Qvalue 1
	_ -> error "parseAcceptLanguage: never occur"

data AcceptEncoding
	= AcceptEncoding String Qvalue
	deriving Show

showAcceptEncoding :: AcceptEncoding -> String
showAcceptEncoding (AcceptEncoding ae qv) = ae ++ showQvalue qv

parseAcceptEncoding :: String -> AcceptEncoding
parseAcceptEncoding src = case span (/= ';') src of
	(ae, ';' : qv) -> AcceptEncoding ae $ parseQvalue qv
	(ae, "") -> AcceptEncoding ae $ Qvalue 1
	_ -> error "parseAcceptEncoding: never occur"

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

data Response = Response {
	responseVersion :: Version,
	responseStatusCode :: StatusCode,
	responseDate :: UTCTime,
	responseContentLength :: ContentLength,
	responseContentType :: ContentType,
	responseOthers :: [(String, String)],
	responseBody :: String
 } deriving Show

parseResponse :: [String] -> Response
parseResponse (h : t) = let (v, sc) = parseResponseLine h in
	parseResponseSep v sc $ map separate t
	where
	separate i = let (k, ':' : ' ' : v) = span (/= ':') i in (k, v)

parseResponseSep :: Version -> StatusCode -> [(String, String)] -> Response
parseResponseSep v sc kvs = Response {
	responseVersion = v,
	responseStatusCode = sc,
	responseDate = readTime defaultTimeLocale "%a, %d %b %Y %H:%M:%S" .
		initN 4 . fromJust $ lookup "Date" kvs,
	responseContentLength = ContentLength . read . fromJust $
		lookup "Content-Length" kvs,
	responseContentType = parseContentType . fromJust $
		lookup "Content-Type" kvs,
	responseOthers = filter ((`notElem` responseKeys) . fst) kvs,
	responseBody = ""
 }

responseKeys :: [String]
responseKeys = ["Date", "Content-Length", "Content-Type"]

initN :: Int -> [a] -> [a]
initN n lst = take (length lst - n) lst

parseResponseLine :: String -> (Version, StatusCode)
parseResponseLine src = case span (/= ' ') src of
	(vs, ' ' : scs) -> (parseVersion vs, parseStatusCode scs)
	_ -> error "parseResponseLine: bad response line"

parseStatusCode :: String -> StatusCode
parseStatusCode ('2' : '0' : '0' : _) = OK
parseStatusCode _ = error "parseStatusCode: bad status code"

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

parseContentType :: String -> ContentType
parseContentType ct = case span (/= '/') ct of
	(t, '/' : st) -> ContentType (t, st)
	_ -> error "parseContentType: bad Content-Type"

showContentType :: ContentType -> String
showContentType (ContentType (t, st)) = t ++ "/" ++ st

showTime :: UTCTime -> String
showTime = formatTime defaultTimeLocale "%a, %d %b %Y %H:%M:%S GMT"
