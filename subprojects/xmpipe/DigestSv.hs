{-# LANGUAGE OverloadedStrings #-}

module DigestSv (
	DigestResponse(..),
	sampleDR,
	responseToKvs,
	) where

import Digest

sampleDR :: DigestResponse
sampleDR = DR {
	drUserName = "yoshikuni",
	drRealm = "localhost",
	drPassword = "password",
	drCnonce = "00DEADBEEF00",
	drNonce = "90972262-92fe-451d-9526-911f5b8f6e34",
	drNc = "00000001",
	drQop = "auth",
	drDigestUri = "xmpp/localhost",
	drCharset = "utf-8"
	}
