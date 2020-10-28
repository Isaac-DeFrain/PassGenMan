module Types where

import qualified Data.ByteArray as BA
import Data.String
import GHC.Generics (Generic(..))

type Username = String

type Password = String

type Service = String

data Affirmative =
    Y
    deriving (Eq)

data ServiceData = ServiceData
    { username :: Username
    , password :: Password
    } deriving (Eq, Ord, Show)

deriving instance Generic Password

instance BA.ByteArrayAccess Password where
    length = BA.length
    withByteArray = BA.withByteArray
    copyByteArrayToPtr = BA.copyByteArrayToPtr

instance Data.String.IsString (Maybe Password) where
    fromString = read
