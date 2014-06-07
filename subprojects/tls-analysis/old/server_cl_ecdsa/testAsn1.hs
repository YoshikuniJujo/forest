{-# LANGUAGE OverloadedStrings #-}

import Data.ASN1.Encoding
import Data.ASN1.Types
import Data.ASN1.Error
import Data.ASN1.BinaryEncoding

some :: Either ASN1Error [ASN1]
some = decodeASN1' DER "\x30\x0a\x02\x03\x0f\xff\xff\x02\x03\x1f\x1f\x1f"
