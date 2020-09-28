module Lib
    ( users
    , services
    , createUser
    , removeUser
    , verifyPwd
    , addServiceManualPassword
    , addServiceRandomPassword
    , removeService
    , changePgmPassword
    , changePgmUsername
    , changeServiceUsername
    , changeServicePasswordRandom
    , changeServicePasswordManual
    , getServiceData
    , getServicePassword
    , getServiceUsername
    , getAllServiceData
    ) where

import Data.Char (toLower)
import Data.List (sort)
import Types

-- import Control.Exception
import Control.Monad (replicateM, when)
import qualified Crypto.Hash as Crypto
import qualified Data.ByteString.Char8 as BS
import qualified System.Directory as Dir
import qualified System.IO as Sys
import Test.RandomStrings (onlyPrintable, randomASCII, randomString)

-- TODO: error handling?
-- | list of known users
users :: IO [String]
users = do
    dir <- getPgmDir
    sort . map removeDot <$> Dir.listDirectory dir
  where
    removeDot = drop 1

-- | list of services registered to the given user
services :: Username -> Password -> IO [String]
services usr pwd = do
    verified <- verifyPwd usr pwd
    if verified
        then do
            usrServices <- getUserServicesDir usr
            sort . map dropDot <$> Dir.listDirectory usrServices
        else error "Incorrect password!"
  where
    dropDot = drop 1

-- | create new user directory
-- TODO: .services subdirectory encrypted/permissioned/etc.
createUser :: Username -> Password -> IO ()
createUser usr pwd = do
    exists <- doesUserExist usr
    if not exists
        then do
            srvDir <- getUserServicesDir usr
            pwdFile <- getUserPwdFilePath usr
            Dir.createDirectoryIfMissing True srvDir
            Sys.writeFile pwdFile $ hashStr ++ "\n"
            contents <- Sys.readFile pwdFile
            putStrLn contents
        else error
                 "User already exists! If you desire to overwrite this user, remove them and create them again."
  where
    hashStr = sha256 pwd

-- ^ remove a PassGenMan user
removeUser :: Username -> Password -> IO ()
removeUser usr pwd = do
    verified <- verifyPwd usr pwd
    if verified
        then do
            putStrLn $
                concat
                    [ "Are you sure you want to remove "
                    , usr
                    , "'s account? (y = yes)"
                    ]
            response <- getLine
            when (map toLower response == "y") $ do
                usrDir <- getUserDir usr
                Dir.removeDirectoryRecursive usrDir
        else error "Incorrect username/password!"

-- | verify the given username's password
verifyPwd :: Username -> Password -> IO Bool
verifyPwd usr pwd = do
    exists <- doesUserExist usr
    if exists
        then do
            pwdHash <- getUserPwdHash usr
            return $ sha256 pwd == pwdHash
        else error "User does not exist!"

-- | pseudorandomly create service password
addServiceRandomPassword ::
       Username -- ^ PassGenMan username
    -> Password -- ^ PassGenMan password
    -> Service
    -> Username -- ^ service username
    -> Int -- ^ required length of password >= 8
    -> IO ()
addServiceRandomPassword usr pwd srv susr len = do
    verified <- verifyPwd usr pwd
    if verified
    -- check if service is already registerd
    -- initialize randomness
        then do
            serviceFilePath <- getUserServiceFilePath usr srv
            if len >= 8
                then do
                    rpwd <- randomPwd len
                    Sys.writeFile serviceFilePath $ unlines [susr, rpwd]
                else do
                    rpwd <- randomPwd 8
                    Sys.writeFile serviceFilePath $ unlines [susr, rpwd]
        else error "Incorrect username/password!"

-- | create service with manual password
addServiceManualPassword ::
       Username -- ^ PassGenMan username
    -> Password -- ^ PassGenMan password
    -> Service
    -> Username -- ^ service username
    -> Password -- ^ service password
    -> IO ()
addServiceManualPassword usr pwd srv srvUsr srvPwd = do
    verified <- verifyPwd usr pwd
    if verified
        then do
            putStrLn "Confirm new password: "
            newPwd <- getLine
            if newPwd == srvPwd
                then do
                    srvFilePath <- getUserServiceFilePath usr srv
                    Sys.writeFile srvFilePath $ unlines [srvUsr, srvPwd]
                else error "Passwords do not match! Try again."
        else error "Incorrect username/password!"

-- | remove the specified service from the given user
removeService :: Username -> Password -> Service -> IO ()
removeService usr pwd srv = do
    exists <- doesServiceExist usr pwd srv
    if exists
        then do
            srvFilePath <- getUserServiceFilePath usr srv
            Dir.removeFile srvFilePath
        else error $ concat [srv, " is not a service registered to ", usr, " !"]

-- | retrieve service username
getServiceUsername :: Username -> Password -> Service -> IO String
getServiceUsername usr pwd srv = do
    exists <- doesServiceExist usr pwd srv
    if exists
        then do
            (_, hdl) <- getServicePathReadHdl usr srv
            [srvUN, _] <- getNlines 2 hdl
            Sys.hClose hdl
            return srvUN
        else error "Service does not exist!"

-- | retrieve service password
getServicePassword :: Username -> Password -> Service -> IO String
getServicePassword usr pwd srv = do
    exists <- doesServiceExist usr pwd srv
    if exists
        then do
            (_, hdl) <- getServicePathReadHdl usr srv
            [_, srvPwd] <- getNlines 2 hdl
            Sys.hClose hdl
            return srvPwd
        else error "Service does not exist!"

-- | retrieve service (name, username, password)
getServiceData ::
       Username -> Password -> Service -> IO (Service, Username, Password)
getServiceData usr pwd srv = do
    exists <- doesServiceExist usr pwd srv
    if exists
        then do
            (_, hdl) <- getServicePathReadHdl usr srv
            serviceData <- getNlines 2 hdl
            Sys.hClose hdl
            return $ serviceTuple serviceData
        else error "Service does not exist!"
  where
    serviceTuple l = (srv, head l, l !! 1)

-- | list all service data registered to given user
getAllServiceData :: Username -> Password -> IO [(Service, Username, Password)]
getAllServiceData usr pwd = mapM (getServiceData usr pwd) =<< services usr pwd

-- | change PassGenMan password
changePgmPassword ::
       Username
    -> Password -- ^ old PGM password
    -> Password -- ^ new PGM password
    -> IO ()
changePgmPassword usr old new = do
    verified <- verifyPwd usr old
    if verified
        then do
            pwdFilePath <- getUserPwdFilePath usr
            putStrLn "Confirm new password: "
            pwd <- getLine
            if pwd == new
                then Sys.writeFile pwdFilePath $ sha256 new ++ "\n"
                else error "Passwords do not match! Try again."
        else error "Incorrect username/password!"

-- | change PassGenMan username
changePgmUsername ::
       Username -- ^ old PGM username
    -> Password
    -> Username -- ^ new PGM username
    -> IO ()
changePgmUsername usr pwd new = do
    verified <- verifyPwd usr pwd
    if verified
        then do
            pgmDir <- getPgmDir
            usrDir <- getUserDir usr
            Dir.renameDirectory usrDir $ pgmDir ++ "/." ++ new
        else error "Incorrect username/password!"

-- | pseudorandomly generate new service password
changeServicePasswordRandom ::
       Username -- ^ PassGenMan username
    -> Password -- ^ PassGenMan password
    -> Service
    -> Int -- ^ length of new service password
    -> IO ()
changeServicePasswordRandom usr pwd srv len = do
    exists <- doesServiceExist usr pwd srv
    when exists $ do
        (srvFilePath, hdl) <- getServicePathReadHdl usr srv
        srvUN <- Sys.hGetLine hdl
        new <- randomPwd len
        Sys.hClose hdl
        hdl' <- Sys.openFile srvFilePath Sys.WriteMode
        Sys.hPutStrLn hdl' $ unlines [srvUN, new]
        Sys.hClose hdl'
        putStrLn $ concat ["New ", srv, " password for ", srvUN, ": ", new]

-- | manually change service password
changeServicePasswordManual ::
       Username -- ^ PassGenMan username
    -> Password -- ^ PassGenMan password
    -> Service
    -> Password -- ^ new service password
    -> IO ()
changeServicePasswordManual usr pwd srv srvPwd = do
    exists <- doesServiceExist usr pwd srv
    if exists
        then do
            (srvFilePath, hdl) <- getServicePathReadHdl usr srv
            srvUN <- Sys.hGetLine hdl
            Sys.hClose hdl
            putStrLn "confirm new password: "
            newPwd <- getLine
            if newPwd == srvPwd
                then do
                    hdl' <- Sys.openFile srvFilePath Sys.WriteMode
                    Sys.hPutStrLn hdl' $ unlines [srvUN, srvPwd]
                    Sys.hClose hdl'
                    putStrLn $
                        concat
                            ["New ", srv, " password for ", srvUN, ": ", srvPwd]
                else error "Passwords do not match! Try again."
        else error "Service does not exist!"

-- | pseudorandomly generate new service password
changeServiceUsername ::
       Username -- ^ PassGenMan username
    -> Password -- ^ PassGenMan password
    -> Service
    -> Username -- ^ new service username
    -> IO ()
changeServiceUsername usr pwd srv new = do
    exists <- doesServiceExist usr pwd srv
    when exists $ do
        (srvFilePath, hdl) <- getServicePathReadHdl usr srv
        [_, srvPwd] <- getNlines 2 hdl
        Sys.hClose hdl
        hdl' <- Sys.openFile srvFilePath Sys.WriteMode
        Sys.hPutStrLn hdl' $ unlines [new, srvPwd]
        Sys.hClose hdl'
        putStrLn $ concat ["New ", map toLower srv, " username: ", new]

----------------------
-- helper functions --
----------------------
-- for convenience
sha256 :: Password -> String
sha256 = show . Crypto.hashWith Crypto.SHA256 . BS.pack

-- | verify existence of user
doesUserExist :: Username -> IO Bool
doesUserExist usr = elem usr <$> users

-- | verify existence of service for user
doesServiceExist :: Username -> Password -> Service -> IO Bool
doesServiceExist usr pwd srv = do
    verified <- verifyPwd usr pwd
    if verified
        then elem (map toLower srv) <$> services usr pwd
        else error "Incorrect username/password!"

-- | PassGenMan directory
getPgmDir :: IO String
getPgmDir = Dir.getAppUserDataDirectory "PassGenMan"

-- | file path for given user
getUserDir :: Username -> IO FilePath
getUserDir usr = Dir.getAppUserDataDirectory $ "PassGenMan/." ++ usr

-- | password file path for given user
getUserPwdFilePath :: Username -> IO FilePath
getUserPwdFilePath usr =
    Dir.getAppUserDataDirectory $ "PassGenMan/." ++ usr ++ "/.pwd"

-- | file path for given service and user
getUserServiceFilePath :: Username -> Service -> IO FilePath
getUserServiceFilePath usr srv =
    Dir.getAppUserDataDirectory $
    "PassGenMan/." ++ usr ++ "/.services/." ++ map toLower srv

-- | services directory for given user
getUserServicesDir :: Username -> IO FilePath
getUserServicesDir usr =
    Dir.getAppUserDataDirectory $ "PassGenMan/." ++ usr ++ "/.services"

-- | retrieve user's password hash
getUserPwdHash :: Username -> IO String
getUserPwdHash usr = do
    pwdFilePath <- getUserPwdFilePath usr
    exists <- Dir.doesFileExist pwdFilePath
    if exists
        then do
            hdl <- Sys.openFile pwdFilePath Sys.ReadMode
            contents <- Sys.hGetContents hdl
            return $ init contents
        else error "User does not exist!"

-- | generate random password of given length
randomPwd :: Int -> IO String
randomPwd = randomString $ onlyPrintable randomASCII

getServicePathReadHdl :: Username -> Service -> IO (FilePath, Sys.Handle)
getServicePathReadHdl usr srv = do
    srvFilePath <- getUserServiceFilePath usr srv
    hdl <- Sys.openFile srvFilePath Sys.ReadMode
    return (srvFilePath, hdl)

getNlines :: Int -> Sys.Handle -> IO [String]
getNlines n hdl = replicateM n $ Sys.hGetLine hdl
