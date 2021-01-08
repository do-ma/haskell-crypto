-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Internals of @crypto_sign@.
module NaCl.Sign.Internal
  ( Signature,
    toSignature,
    SecretKey,
    toSecretKey,
    PublicKey,
    toPublicKey,
    Seed,
    toSeed,
    keypair,
    seededKeypair,
    create,
    createDetached,
    open,
    verifyDetached,
  )
where

import Data.ByteArray (ByteArray, ByteArrayAccess, ScrubbedBytes, allocRet, length, withByteArray)
import Data.ByteArray.Sized (SizedByteArray, alloc, sizedByteArray)
import qualified Data.ByteArray.Sized as Sized (alloc, allocRet)
import Data.ByteString (ByteString)
import Data.Functor (void)
import Data.Proxy (Proxy (Proxy))
import Foreign.Ptr (nullPtr)
import qualified Libsodium as Na
import Prelude hiding (length)

-- | A type alias for detached signatures.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@,
type Signature a = SizedByteArray Na.CRYPTO_SIGN_BYTES a

-- | Convert bytes to a detached signature
toSignature :: ByteArrayAccess bs => bs -> Maybe (Signature bs)
toSignature = sizedByteArray

-- | Seed that is used to make signature keypair.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@, but, since this
-- is used to create a secret key, it is better to use @ScrubbedBytes@.
type Seed a = SizedByteArray Na.CRYPTO_SIGN_SEEDBYTES a

-- | Convert bytes to a Seed
toSeed :: ByteArrayAccess  bs => bs -> Maybe (Seed bs)
toSeed = sizedByteArray

-- | Secret key that can be used for creating a signature.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@, but, since this
-- is a secret key, it is better to use @ScrubbedBytes@.
type SecretKey a = SizedByteArray Na.CRYPTO_SIGN_SECRETKEYBYTES a

-- | Convert bytes to a secret key.
toSecretKey :: ByteArrayAccess bytes => bytes -> Maybe (SecretKey bytes)
toSecretKey = sizedByteArray

-- | Public key that can be used for verifyiing a signature.
--
-- This type is parametrised by the actual data type that contains
-- bytes. This can be, for example, a @ByteString@.
type PublicKey a = SizedByteArray Na.CRYPTO_SIGN_PUBLICKEYBYTES a

-- | Convert bytes to a public key.
toPublicKey :: ByteArrayAccess bytes => bytes -> Maybe (PublicKey bytes)
toPublicKey = sizedByteArray

-- | Generate a new 'SecretKey' together with its 'PublicKey'.
--
-- Note: this function is not thread-safe (since the underlying
-- C function is not thread-safe both in Sodium and in NaCl)!
-- Either make sure there are no concurrent calls or see
-- @Crypto.Init@ in
-- <https://hackage.haskell.org/package/crypto-sodium crypto-sodium>
-- to learn how to make this function thread-safe.
--
-- What this function does is really:
--  1. In Sized.allocRet invocation:
--    A. Allocate 64 bytes by `Proxy` that is inferred to be `:: Proxy 64` because
--       `64 ~ Na.CRYPTO_SIGN_SECRETKEYBYTES` and `SecretKey a = SizedByteArray Na.CRYPTO_SIGN_SECRETKEYBYTES a`.
--    B. Run underlying function (2) and return a tuple the first element of which
--       is its output, and the second element of which is bytes that end up under the
--       pointer bound by (1).
--  2. In Sized.alloc invocation, infer the size of public key and:
--    A. Run Na.crypto_sign_keypair that populates data under pkPtr and skPtr
--    B. Return just the data under pkPtr from `alloc`
-- This way, data from pkPtr gets into the first element of (1)'s return value!
keypair :: IO (PublicKey ByteString, SecretKey ScrubbedBytes)
keypair =
  -- allocRet returns a tuple consisiting of
  --  1. Whatever underlying `IO a` function returns
  --  2. Contents of allocated Ptr
  Sized.allocRet Proxy $ \skPtr ->
    -- alloc returns contents of pkPtr after executing side effect
    Sized.alloc $ \pkPtr ->
      void $ Na.crypto_sign_keypair pkPtr skPtr

-- | Given a key, generate a new 'SecretKey' together with its 'PublicKey'.
--
-- Note: this function is not thread-safe (since the underlying
-- C function is not thread-safe both in Sodium and in NaCl)!
-- Either make sure there are no concurrent calls or see
-- @Crypto.Init@ in
-- <https://hackage.haskell.org/package/crypto-sodium crypto-sodium>
-- to learn how to make this function thread-safe.
seededKeypair :: Seed ScrubbedBytes -> IO (PublicKey ByteString, SecretKey ScrubbedBytes)
seededKeypair seed =
  Sized.allocRet Proxy $ \skPtr ->
    Sized.alloc $ \pkPtr ->
      withByteArray seed $ \seedPtr ->
        void $ Na.crypto_sign_seed_keypair pkPtr skPtr seedPtr

-- | Sign a message.
create ::
  ( ByteArrayAccess skBytes,
    ByteArrayAccess pt,
    ByteArray ct
  ) =>
  -- | Signer’s secret key
  SecretKey skBytes ->
  -- | Message to sign
  pt ->
  IO ct
create sk msg = do
  (_ret, ct) <-
    allocRet clen $ \ctPtr ->
      withByteArray sk $ \skPtr ->
        withByteArray msg $ \msgPtr -> do
          Na.crypto_sign
            ctPtr
            nullPtr
            msgPtr
            (fromIntegral $ length msg)
            skPtr
  -- _ret can be only 0, so we don’t check it
  -- TODO: Actually, it looks like this function can fail and return
  -- a -1, even though this is not documented :/.
  pure ct
  where
    clen :: Int
    clen = fromIntegral Na.crypto_sign_bytes + length msg

-- | Sign a message and return detached signature.
createDetached ::
  ( ByteArrayAccess skBytes,
    ByteArrayAccess pt,
    ByteArray sig
  ) =>
  -- | Signer’s secret key
  SecretKey skBytes ->
  -- | Message to sign
  pt ->
  IO (Signature sig)
createDetached sk msg = do
  alloc $ \sigPtr ->
    withByteArray sk $ \skPtr ->
      withByteArray msg $ \msgPtr -> do
        void $ Na.crypto_sign_detached
          sigPtr
          nullPtr
          msgPtr
          (fromIntegral $ length msg)
          skPtr
-- _ret can be only 0, so we don’t check it
  -- TODO: Actually, it looks like this function can fail and return
  -- a -1, even though this is not documented :/.

-- | Verify the signature of a signed message.
open ::
  ( ByteArrayAccess pkBytes,
    ByteArray pt,
    ByteArrayAccess ct
  ) =>
  -- | Signer’s public key
  PublicKey pkBytes ->
  -- | Signed message
  ct ->
  IO (Maybe pt)
open pk ct = do
  (ret, msg) <-
    allocRet mlen $ \msgPtr ->
      withByteArray pk $ \pkPtr ->
        withByteArray ct $ \ctPtr -> do
          Na.crypto_sign_open
            msgPtr
            nullPtr
            ctPtr
            (fromIntegral $ length ct)
            pkPtr
  if ret == 0
    then pure $ Just msg
    else pure Nothing
  where
    mlen :: Int
    mlen = length ct - fromIntegral Na.crypto_sign_bytes

verifyDetached ::
  (ByteArrayAccess pkBytes, ByteArrayAccess msg) =>
  Signature ByteString ->
  msg ->
  PublicKey pkBytes ->
  IO Bool
verifyDetached sig msg pk = do
  x <- withByteArray sig $ \sigPtr -> do
    withByteArray msg $ \msgPtr -> do
      withByteArray pk $ \pkPtr -> do
        Na.crypto_sign_verify_detached
          sigPtr
          msgPtr
          ((fromIntegral . length) msg)
          pkPtr
  return $ x == 0