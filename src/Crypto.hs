{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto
    ( encrypt
    , decrypt
    , salt'
    ) where

import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (BlockCipher(..), Cipher(..), IV, makeIV)
import Crypto.Error (CryptoError(..), CryptoFailable(..))
import qualified Crypto.Hash as Hash
import qualified Crypto.Random.Types as CRT
import Data.ByteArray (ByteArray)
import qualified Data.ByteString.Char8 as BS
import Types

-- | Not required, but most general implementation
data Key c a where
    Key :: (BlockCipher c, ByteArray a) => a -> Key c a

mkIV :: BS.ByteString -> Maybe (IV AES256)
mkIV = makeIV

-- | Initialize a block cipher
initCipher :: (BlockCipher c, ByteArray a) => Key c a -> Either CryptoError c
initCipher (Key k) =
    case cipherInit k of
        CryptoFailed e -> Left e
        CryptoPassed a -> Right a

-- | salt for password hashes
salt' :: IO String
salt' = filter (/= '\n') . BS.unpack <$> CRT.getRandomBytes 32

encrypt' ::
       (BlockCipher c, ByteArray a)
    => Key c a
    -> IV c
    -> a
    -> Either CryptoError a
encrypt' secretKey iv msg =
    case initCipher secretKey of
        Left err -> Left err
        Right c -> Right $ ctrCombine c iv msg

decrypt' ::
       (BlockCipher c, ByteArray a)
    => Key c a
    -> IV c
    -> a
    -> Either CryptoError a
decrypt' = encrypt'

encrypt ::
       Password
    -> String -- ^ message to encrypt
    -> IO String -- ^ encrypted msg
encrypt pwd msg = do
    let secret = hashAndSize 32 pwd
        secretKey = Key secret
    case mkIV $ BS.take 16 secret of
        Nothing -> error "Failed to generate an initialization vector."
        Just iv ->
            case encrypt' secretKey iv $ BS.pack msg of
                Left err -> error $ show err
                Right eMsg -> return $ BS.unpack eMsg

decrypt ::
       Password
    -> String -- ^ message to decrypt
    -> IO String -- ^ decrypted msg
decrypt pwd msg = do
    let secret = hashAndSize 32 pwd
        secretKey = Key secret
    case mkIV $ BS.take 16 secret of
        Nothing -> error "Failed to generate an initialization vector."
        Just iv ->
            case decrypt' secretKey iv $ BS.pack msg of
                Left err -> error $ show err
                Right eMsg -> return $ BS.unpack eMsg

hashAndSize :: Int -> String -> BS.ByteString
hashAndSize n = BS.pack . take n . show . Hash.hashWith Hash.SHA256 . BS.pack
