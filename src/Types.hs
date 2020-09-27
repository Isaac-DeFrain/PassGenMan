{-# LANGUAGE FlexibleInstances, DeriveGeneric, StandaloneDeriving
  #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Types where

import qualified Data.ByteArray as BA
import GHC.Generics (Generic(..))

type Username = String

type Password = String

type Service = String

type MustInclude = String

type MustExclude = String

data ServiceData = ServiceData
    { username :: Username
    , password :: Password
    } deriving (Eq, Ord, Show)

deriving instance Generic Password

instance BA.ByteArrayAccess Password where
    length = BA.length
    withByteArray = BA.withByteArray
    copyByteArrayToPtr = BA.copyByteArrayToPtr
