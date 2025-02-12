-- SPDX-FileCopyrightText: 2020 Serokell
--
-- SPDX-License-Identifier: MPL-2.0
{-# OPTIONS_HADDOCK not-home #-}

-- ! This module merely re-exports definitions from the corresponding
-- ! module in NaCl and alters the Haddock to make it more specific
-- ! to crypto-sodium. So, the docs should be kept more-or-less in sync.

-- | Public-key signatures.
--
-- It is best to import this module qualified:
--
-- @
-- import qualified Crypto.Sign as Sign
--
-- signed = Sign.'create' sk message
-- verified = Sign.'open' pk signed
-- @
--
-- Functions in this modules work with /combined/ signatures.
-- This means that when you sign a message, it will be copied as is
-- and then a signature will be prepended. So you should treat the
-- resulting value as a transparent (because it is not encrypted)
-- package with a signature attached on top.
--
-- Instead of accessing the message directly, you should use
-- 'open', which will verify the signature and return a copy of the
-- original message only if the signature was valid.
module Crypto.Sign
  ( -- * Keys
    PublicKey,
    toPublicKey,
    SecretKey,
    toSecretKey,
    keypair,

    -- * Signing/verifying
    create,
    open,
  )
where

import NaCl.Sign (PublicKey, SecretKey, create, keypair, open, toPublicKey, toSecretKey)
