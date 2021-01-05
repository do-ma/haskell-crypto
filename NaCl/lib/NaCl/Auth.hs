-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0

-- | Symmetric message authentication.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified NaCl.Auth as Auth
--
-- authenticator = Auth.'create' key message
-- if Secretbox.'verify' key message authenticator
-- then {- Ok! -}
-- else {- Fail! -}
-- @
--
-- This is @crypto_auth_*@ from NaCl.
module NaCl.Auth
  ( Key,
    toKey,
    Authenticator,
    toAuthenticator,
    create,
    verify,
  )
where

import Data.ByteArray (ByteArray, ByteArrayAccess)
import NaCl.Auth.Internal (Authenticator, Key, toAuthenticator, toKey)
import qualified NaCl.Auth.Internal as I
import System.IO.Unsafe (unsafePerformIO)

-- | Create an authenticator for a message.
--
-- @
-- authenticator = Auth.create key message
-- @
--
-- *   @key@ is the secret key used for authentication.
--     See "NaCl.Secretbox" for how to crete it, as the idea is the same.
--
-- *   @message@ is the data you are authenticating.
--
-- This function produces authentication data, so if anyone modifies the message,
-- @verify@ will return @False@.
create ::
  ( ByteArray authBytes,
    ByteArrayAccess keyBytes,
    ByteArrayAccess msg
  ) =>
  -- | Secret key.
  Key keyBytes ->
  -- | Message to authenticate.
  msg ->
  Authenticator authBytes
create key msg = do
  -- This IO is safe, because it is pure.
  unsafePerformIO $ I.create key msg

-- | Verify an authenticator for a message.
--
-- @
-- isValid = Auth.verify key message authenticator
-- @
--
-- * @key@ and @message@ are the same as when creating the authenticator.
-- * @authenticator@ is the output of 'create'.
--
-- This function will return @False@ if the message is not exactly the same
-- as it was when the authenticator was created.
verify ::
  ( ByteArrayAccess authBytes,
    ByteArrayAccess msg,
    ByteArrayAccess keyBytes
  ) =>
  -- | Secret key.
  Key keyBytes ->
  -- | Authenticated message.
  msg ->
  -- | Authenticator tag.
  Authenticator authBytes ->
  Bool
verify key msg auth = do
  -- This IO is safe, because it is pure.
  unsafePerformIO $ I.verify key msg auth
