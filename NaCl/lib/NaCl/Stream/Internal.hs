{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# OPTIONS_GHC -Wno-redundant-constraints #-}

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Internals of @crypto_stream@.
module NaCl.Stream.Internal
  ( Key,
    toKey,
    Nonce,
    toNonce,
    MaxStreamSize,
    generate,
    xor,
  )
where

import Data.ByteArray (ByteArray, ByteArrayAccess, allocRet, length, withByteArray)
import Data.ByteArray.Sized (ByteArrayN, SizedByteArray, sizedByteArray)
import qualified Data.ByteArray.Sized as Sized (allocRet)
import Data.Proxy (Proxy (Proxy))
import GHC.TypeLits (natVal, type (<=))
import qualified Libsodium as Na
import Prelude hiding (length)

-- | Encryption key that can be used for Stream.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@, but, since this
-- is a secret key, it is better to use @ScrubbedBytes@.
type Key a = SizedByteArray Na.CRYPTO_STREAM_KEYBYTES a

-- | Make a 'Key' from an arbitrary byte array.
--
-- This function returns @Just@ if and only if the byte array has
-- the right length to be used as a key with a Stream.
toKey :: ByteArrayAccess ba => ba -> Maybe (Key ba)
toKey = sizedByteArray

-- | Nonce that can be used for Stream.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
type Nonce a = SizedByteArray Na.CRYPTO_STREAM_NONCEBYTES a

-- | Make a 'Nonce' from an arbitrary byte array.
--
-- This function returns @Just@ if and only if the byte array has
-- the right length to be used as a nonce with a Stream.
toNonce :: ByteArrayAccess ba => ba -> Maybe (Nonce ba)
toNonce = sizedByteArray

-- | The maximum size of the stream produced by 'generate'.
type MaxStreamSize = 18446744073709551615 -- = 2^64 - 1 (internal 64-bit counter)

-- | Generate a stream of pseudo-random bytes.
generate ::
  forall key nonce n ct.
  ( ByteArrayAccess key,
    ByteArrayAccess nonce,
    ByteArrayN n ct,
    n <= MaxStreamSize
  ) =>
  -- | Secret key
  Key key ->
  -- | Nonce
  Nonce nonce ->
  IO ct
generate key nonce = do
  (_ret, ct) <-
    Sized.allocRet (Proxy :: Proxy n) $ \ctPtr ->
      withByteArray key $ \keyPtr ->
        withByteArray nonce $ \noncePtr ->
          Na.crypto_stream
            ctPtr
            (fromIntegral $ natVal (Proxy :: Proxy n))
            noncePtr
            keyPtr
  -- _ret can be only 0, so we don’t check it
  pure ct

-- | Encrypt/decrypt a message.
xor ::
  ( ByteArrayAccess key,
    ByteArrayAccess nonce,
    ByteArrayAccess pt,
    ByteArray ct
  ) =>
  -- | Secret key
  Key key ->
  -- | Nonce
  Nonce nonce ->
  -- | Input (plain/cipher) text
  pt ->
  IO ct
xor key nonce msg = do
  (_ret, ct) <-
    allocRet clen $ \ctPtr ->
      withByteArray key $ \keyPtr ->
        withByteArray nonce $ \noncePtr ->
          withByteArray msg $ \msgPtr -> do
            Na.crypto_stream_xor
              ctPtr
              msgPtr
              (fromIntegral $ length msg)
              noncePtr
              keyPtr
  -- _ret can be only 0, so we don’t check it
  pure ct
  where
    clen :: Int
    clen = length msg
