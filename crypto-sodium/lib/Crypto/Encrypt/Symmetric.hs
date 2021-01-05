-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0
{-# OPTIONS_HADDOCK not-home #-}

-- ! This module merely re-exports definitions from the corresponding
-- ! module in NaCl and alters the Haddock to make it more specific
-- ! to crypto-sodium. So, the docs should be kept more-or-less in sync.

-- | Symmetric authenticated encryption.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified Crypto.Encrypt.Symmetric as Symmetric
--
-- encrypted = Symmetric.'encrypt' key nonce message
-- decrypted = Symmetric.'decrypt' key nonce encrypted
-- @
--
-- In NaCl this is know as a “Secretbox”. One way to think about it
-- is to imagine that you are putting data into a box protected by a
-- secret key. You “create” such a box using 'encrypt', store it somewhere
-- (it is just a sequence of bytes), and when you need it in the
-- future, you “open” it with 'decrypt' using the same secret key.
module Crypto.Encrypt.Symmetric
  ( -- * Keys
    Key,
    toKey,

    -- * Nonce
    Nonce,
    toNonce,

    -- * Encryption/decryption
    encrypt,
    decrypt,
  )
where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import NaCl.Secretbox (Key, Nonce, toKey, toNonce)
import qualified NaCl.Secretbox as NaCl.Secretbox

-- | Encrypt a message.
--
-- @
-- encrypted = Symmetric.encrypt key nonce message
-- @
--
-- *   @key@ is the secret key used for encryption. See "Crypto.Key" for how
--     to get one.
--
-- *   @nonce@ is an extra noise that is required for security.
--     See "Crypto.Nonce" for how to work with it.
--
-- *   @message@ is the data you are encrypting.
--
-- This function adds authentication data, so if anyone modifies the cyphertext,
-- 'open' will refuse to decrypt it.
encrypt ::
  ( ByteArrayAccess keyBytes,
    ByteArrayAccess nonceBytes,
    ByteArrayAccess ptBytes,
    ByteArray ctBytes
  ) =>
  -- | Secret key
  Key keyBytes ->
  -- | Nonce
  Nonce nonceBytes ->
  -- | Plaintext message
  ptBytes ->
  ctBytes
encrypt = NaCl.Secretbox.create

-- | Decrypt a message.
--
-- @
-- decrypted = Symmetric.decrypt key nonce encrypted
-- @
--
-- * @key@ and @nonce@ are the same that were used for encryption.
-- * @encrypted@ is the output of 'create'.
--
-- This function will return @Nothing@ if the encrypted message was tampered
-- with after it was encrypted.
decrypt ::
  ( ByteArrayAccess keyBytes,
    ByteArrayAccess nonceBytes,
    ByteArray ptBytes,
    ByteArrayAccess ctBytes
  ) =>
  -- | Secret key
  Key keyBytes ->
  -- | Nonce
  Nonce nonceBytes ->
  -- | Encrypted message (cyphertext)
  ctBytes ->
  Maybe ptBytes
decrypt = NaCl.Secretbox.open
