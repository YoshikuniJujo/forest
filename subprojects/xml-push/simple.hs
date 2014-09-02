import XmlPusher
import System.IO

main :: IO ()
main = testPusher
	(undefined :: SimplePusher Handle)
	Zero
	("read.xml", "tmp/write.xml")
