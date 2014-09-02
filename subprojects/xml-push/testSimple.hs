import XmlPusher
import System.IO

main :: IO ()
main = testPusher
	(undefined :: SimplePusher Handle)
	Zero
	("xml/read.xml", "tmp/write.xml")
