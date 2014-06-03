{-# LANGUAGE OverloadedStrings #-}

import Text.XML (def)
import qualified Text.XML as XML

main :: IO ()
main = do
	xml <- XML.readFile def "sample.xml"
	print xml
