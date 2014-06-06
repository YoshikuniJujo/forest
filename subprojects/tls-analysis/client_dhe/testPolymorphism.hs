
class Some s where
	me :: s
	hello :: s -> String
	noHello :: s -> String
	greeting :: s -> Bool

instance Some World where
	me = World
	hello _ = "Hello, world!"
	noHello _ = "world!"
	greeting _ = True

instance Some NoWorld where
	me = NoWorld
	hello _ = "Hello, no world!"
	noHello _ = "no world!"
	greeting _ = False

data World = World deriving Show
data NoWorld = NoWorld deriving Show

{-
myHello :: Some s => IO s
myHello = let
	io = putStrLn (hello me) >> return me
	t = undefined in do
		return t `asTypeOf` io
		io
		-}

myHello2 :: Some s => IO s
myHello2 = do
	let i = me
	if greeting i
		then putStrLn $ hello i
		else putStrLn $ noHello i
	return i

myHello3 :: Some s => IO s
myHello3 = do
	let	i = undefined
		j = if greeting j then me else undefined
	return $ i `asTypeOf` j
	return j

{-
myHello4 :: Some s => IO s
myHello4 = do
	let i = undefined
	j <- if greeting i then return me else return undefined
	return $ i `asTypeOf` j
	return j

myHello5 :: Some s => IO s
myHello5 = let
	i = undefined
	_ = return i `asTypeOf` io
	io = if greeting i then return (me `asTypeOf` i) else return undefined in
	io
-}

myHello6 :: Some s => IO s
myHello6 = do
	let s = undefined
	mh s `asTypeOf` myHello6
	where
	mh s = if greeting s then return $ me `asTypeOf` s else undefined
