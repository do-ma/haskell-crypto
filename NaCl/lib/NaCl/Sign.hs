-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Public-key signatures.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified NaCl.Sign as Sign
--
-- signed = Sign.'create' sk message
-- verified = Sign.'open' pk signed
-- @
--
-- This is @crypto_sign_*@ from NaCl.
module NaCl.Sign
  ( PublicKey,
    toPublicKey,
    SecretKey,
    toSecretKey,
    Seed,
    toSeed,
    keypair,
    seededKeypair,
    create,
    open,
    toSignature,
    Signature,
    createDetached,
    verifyDetached,
  )
where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import NaCl.Sign.Internal
  ( PublicKey,
    SecretKey,
    Seed,
    Signature,
    keypair,
    toPublicKey,
    toSecretKey,
    toSeed,
    toSignature,
  )
import qualified NaCl.Sign.Internal as I
import System.IO.Unsafe (unsafePerformIO)

-- | Generate keypair from seed.
--
-- Given a key, generated with 'pwhash' (see `crypto-sodium/lib/Crypto/Key.hs`)
-- generate a new 'SecretKey' together with its 'PublicKey'.
seededKeypair ::
  (ByteArray sk, ByteArray pk, ByteArrayAccess seed) =>
  Seed seed ->
  (PublicKey pk, SecretKey sk)
seededKeypair seed =
  unsafePerformIO $ I.seededKeypair seed

-- | Sign a message.
--
-- @
-- signed = Sign.create sk message
-- @
--
-- *   @sk@ is the signer’s secret key, used for authentication.
--
--     This is generated using 'keypair' or 'seededKeypair' and
--     the public part of the key needs to be given to the
--     verifying party in advance.
--
-- *   @message@ is the data you are signing.
--
-- This function will copy the message to a new location
-- and add a signature, so that 'open' will refuce to verify it.
create ::
  ( ByteArrayAccess skBytes,
    ByteArrayAccess ptBytes,
    ByteArray ctBytes
  ) =>
  -- | Signer’s secret key
  SecretKey skBytes ->
  -- | Message to sign
  ptBytes ->
  ctBytes
create sk msg =
  -- This IO is safe, because it is pure.
  unsafePerformIO $ I.create sk msg

-- | Create a detached signature of a message.
--
-- Same as `create`, just in detached mode.
createDetached ::
  (ByteArray sig, ByteArrayAccess skBytes, ByteArrayAccess pt) =>
  SecretKey skBytes ->
  pt ->
  Signature sig
createDetached sk msg =
  unsafePerformIO $ I.createDetached sk msg

-- | Verify a signature.
--
-- @
-- verified = Sign.open pk signed
-- @
--
-- * @pk@ is the signer’s public key.
-- * @signed@ is the output of 'create'.
--
-- This function will return @Nothing@ if the signature on the message
-- is invalid.
open ::
  ( ByteArrayAccess pkBytes,
    ByteArray ptBytes,
    ByteArrayAccess ctBytes
  ) =>
  -- | Signer’s public key
  PublicKey pkBytes ->
  -- | Signed message
  ctBytes ->
  Maybe ptBytes
open pk ct =
  -- This IO is safe, because it is pure.
  unsafePerformIO $ I.open pk ct

-- | Verify a detached signature.
--
-- * @sig@ is detached signature
-- * @msg@ is message that sig supposedly signs
-- * @pk@ is signer's alleged public key
--
-- This function will return @False@ if the signature on the message
-- is invalid.
verifyDetached ::
  (ByteArrayAccess pkBytes, ByteArrayAccess msg, ByteArray sig) =>
  Signature sig ->
  msg ->
  PublicKey pkBytes ->
  Bool
verifyDetached sig msg pk =
  unsafePerformIO $ I.verifyDetached sig msg pk