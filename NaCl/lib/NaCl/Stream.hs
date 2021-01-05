{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- ! This module intentionally does not contain extensive documentation
-- ! as a measure for discouraging its use.

-- | Unauthenticated streaming encryption.
--
-- __Note:__ Unauthenticated encryption is __insecure__ in general.
-- Only use the functions from this modules if you know exactly what you are doing.
-- We only provide this module for compatibility with NaCl.
-- @
--
-- This is @crypto_box_*@ from NaCl.
module NaCl.Stream
  ( Key,
    toKey,
    Nonce,
    toNonce,
    MaxStreamSize,
    generate,
    xor,
  )
where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import Data.ByteArray.Sized (ByteArrayN)
import GHC.TypeLits (type (<=))
import NaCl.Stream.Internal (Key, MaxStreamSize, Nonce, toKey, toNonce)
import qualified NaCl.Stream.Internal as I
import System.IO.Unsafe (unsafePerformIO)

-- | Generate a stream of pseudo-random bytes.
generate ::
  forall n key nonce ct.
  ( ByteArrayAccess key,
    ByteArrayAccess nonce,
    ByteArrayN n ct,
    n <= MaxStreamSize
  ) =>
  -- | Secret key
  Key key ->
  -- | Nonce
  Nonce nonce ->
  ct
generate key nonce =
  -- This IO is safe, because it is pure.
  unsafePerformIO $ I.generate key nonce

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
  ct
xor key nonce msg =
  -- This IO is safe, because it is pure.
  unsafePerformIO $ I.xor key nonce msg
