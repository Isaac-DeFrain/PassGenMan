-- TODO: salt password before hashing
-- TODO: error handling?
-- TODO: automatic backup in specified directory - set up when user is created
module Lib
    ( users
    , services
    , createUser
    , removeUser
    , removeService
    , addServiceManualPassword
    , addServiceRandomPassword
    , changePgmPassword
    , changePgmUsername
    , changeServiceUsername
    , changeServicePasswordRandom
    , changeServicePasswordManual
    , getServiceData
    , getServicePassword
    , getServiceUsername
    , getAllServiceData
    , getUserDir
    , sha256
    , separateContentsInDir
    ) where

import Control.Monad (filterM, replicateM, unless, when)
import Crypto
import qualified Crypto.Hash as Hash
import qualified Data.ByteString.Char8 as BS
import Data.Char (toLower)
import Data.List (sort)
import qualified System.Directory as Dir
import qualified System.IO as Sys
import Test.RandomStrings (onlyPrintable, randomASCII, randomString)
import Types

-- | list of known users
users :: IO [Username]
users = do
    dir <- getPgmDir
    sort . map removeDot <$> Dir.listDirectory dir
  where
    removeDot = drop 1

-- | list of services registered to the given user
services :: Username -> Password -> IO [Service]
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
createUser :: Username -> Password -> IO ()
createUser usr pwd =
    unless ('/' `elem` usr) $ do
        exists <- doesUserExist usr
        if not exists
            then do
                srvDir <- getUserServicesDir usr
                pwdFile <- getUserPwdFilePath usr
                buFile <- getUserBackupFilePath usr
                Dir.createDirectoryIfMissing True srvDir
                Sys.writeFile pwdFile $ hashStr ++ "\n"
                Sys.writeFile buFile ""
            else error
                     "User already exists! If you desire to overwrite this user, remove them and create them again."
  where
    hashStr = sha256 pwd

-- | remove a PassGenMan user
removeUser :: Username -> Password -> IO ()
removeUser usr pwd = do
    verified <- verifyPwd usr pwd
    if verified
        then do
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
        then do
            srvFilePath <- getUserServiceFilePath usr srv
            if len >= 8
                then do
                    rpwd <- randomPwd len
                    encryptUsrPwdAndWrite pwd susr rpwd srvFilePath
                else do
                    rpwd <- randomPwd 8
                    encryptUsrPwdAndWrite pwd susr rpwd srvFilePath
        else error "Incorrect username/password!"

-- | create service with manual password
addServiceManualPassword ::
       Username -- ^ PassGenMan username
    -> Password -- ^ PassGenMan password
    -> Service
    -> Username -- ^ service username
    -> Password -- ^ service password
    -> IO ()
addServiceManualPassword usr pwd srv susr spwd = do
    verified <- verifyPwd usr pwd
    if verified
        then do
            putStrLn "Confirm new password: "
            newPwd <- getLine
            if newPwd == spwd
                then do
                    srvFilePath <- getUserServiceFilePath usr srv
                    encryptUsrPwdAndWrite pwd susr spwd srvFilePath
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
getServiceUsername :: Username -> Password -> Service -> IO Username
getServiceUsername usr pwd srv = do
    exists <- doesServiceExist usr pwd srv
    if exists
        then do
            (_, hdl) <- getServicePathReadHdl usr srv
            [encSUsr, _] <- getNlines 2 hdl
            Sys.hClose hdl
            decrypt pwd encSUsr
        else error "Service does not exist!"

-- | retrieve service password
getServicePassword :: Username -> Password -> Service -> IO Password
getServicePassword usr pwd srv = do
    exists <- doesServiceExist usr pwd srv
    if exists
        then do
            (_, hdl) <- getServicePathReadHdl usr srv
            [_, encSrvPwd] <- getNlines 2 hdl
            Sys.hClose hdl
            decrypt pwd encSrvPwd
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
            serviceTuple serviceData
        else error "Service does not exist!"
  where
    serviceTuple l = do
        usr' <- decrypt pwd $ head l
        pwd' <- decrypt pwd $ l !! 1
        return (srv, usr', pwd')

-- | list all service data registered to given user
getAllServiceData :: Username -> Password -> IO [(Service, Username, Password)]
getAllServiceData usr pwd = mapM (getServiceData usr pwd) =<< services usr pwd

-- | change PassGenMan password
-- TODO: change encryption of all service data
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
        new <- randomPwd len
        encPwd <- encrypt pwd new
        encSUsr <- Sys.hGetLine hdl
        susr <- decrypt pwd encSUsr
        Sys.hClose hdl
        hdl' <- Sys.openFile srvFilePath Sys.WriteMode
        Sys.hPutStrLn hdl' $ unlines [encSUsr, encPwd]
        Sys.hClose hdl'
        putStrLn $ concat ["New ", srv, " password for ", susr, ": ", new]

-- | manually change service password
changeServicePasswordManual ::
       Username -- ^ PassGenMan username
    -> Password -- ^ PassGenMan password
    -> Service
    -> Password -- ^ new service password
    -> IO ()
changeServicePasswordManual usr pwd srv spwd = do
    exists <- doesServiceExist usr pwd srv
    if exists
        then do
            (srvFilePath, hdl) <- getServicePathReadHdl usr srv
            encSUsr <- Sys.hGetLine hdl
            susr <- decrypt pwd encSUsr
            encSPwd <- encrypt pwd spwd
            Sys.hClose hdl
            putStrLn "confirm new password: "
            newPwd <- getLine
            if newPwd == spwd
                then do
                    hdl' <- Sys.openFile srvFilePath Sys.WriteMode
                    Sys.hPutStrLn hdl' $ unlines [encSUsr, encSPwd]
                    Sys.hClose hdl'
                    putStrLn $
                        concat ["New ", srv, " password for ", susr, ": ", spwd]
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
        [_, encSPwd] <- getNlines 2 hdl
        Sys.hClose hdl
        hdl' <- Sys.openFile srvFilePath Sys.WriteMode
        encSUsr <- encrypt pwd new
        Sys.hPutStrLn hdl' $ unlines [encSUsr, encSPwd]
        Sys.hClose hdl'
        putStrLn $ concat ["New ", map toLower srv, " username: ", new]

----------------------
-- helper functions --
----------------------
-- for convenience
sha256 :: Password -> String
sha256 = show . Hash.hashWith Hash.SHA256 . BS.pack

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
getPgmDir :: IO FilePath
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

-- | backup file filepath for given user
getUserBackupFilePath :: Username -> IO FilePath
getUserBackupFilePath usr = do
    usrDir <- getUserDir usr
    return $ usrDir ++ "/.backup"

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
randomPwd :: Int -> IO Password
randomPwd = randomString $ onlyPrintable randomASCII

-- | user's services directory with handle in read mode
getServicePathReadHdl :: Username -> Service -> IO (FilePath, Sys.Handle)
getServicePathReadHdl usr srv = do
    srvFilePath <- getUserServiceFilePath usr srv
    hdl <- Sys.openFile srvFilePath Sys.ReadMode
    return (srvFilePath, hdl)

getNlines :: Int -> Sys.Handle -> IO [String]
getNlines n hdl = replicateM n $ Sys.hGetLine hdl

-- | encrypt service username and password and write to given file
encryptUsrPwdAndWrite :: Password -> Username -> Password -> FilePath -> IO ()
encryptUsrPwdAndWrite p su sp sfp = do
    encSUsr <- encrypt p su
    encSPwd <- encrypt p sp
    Sys.writeFile sfp $ unlines [encSUsr, encSPwd]

-- | set a user's backup directory
setUserBackupDir :: Username -> Password -> FilePath -> IO ()
setUserBackupDir usr pwd buDir = do
    verified <- verifyPwd usr pwd
    if verified
        then do
            exists <- Dir.doesDirectoryExist buDir
            if exists
                then do
                    buFile <- getUserBackupFilePath usr
                    Sys.writeFile buFile $ buDir ++ "\n"
                else error "Backup directory does not exist!"
        else error "Incorrect username/password!"

-- | user back up directory
getUserBackupDir :: Username -> IO (Either String FilePath)
getUserBackupDir usr = do
    buFile <- getUserBackupFilePath usr
    exists <- Dir.doesFileExist buFile
    if exists
        then do
            hdl <- Sys.openFile buFile Sys.ReadMode
            buDir <- Sys.hGetContents hdl
            return $ Right buDir
        else return . Left $ "A backup directory has not been set for " ++ usr

backupUser :: Username -> IO ()
backupUser usr = do
    res <- getUserBackupDir usr
    case res of
        Left err -> putStrLn err
        Right _buDir -> undefined

-- copy user's PGM directory to their backup directory
-- | separates files and directories
-- TODO: make filepaths absolute and recursively list subdirectory contents
separateContentsInDir :: FilePath -> IO ([FilePath], [FilePath])
separateContentsInDir dir = do
    contents <- Dir.listDirectory dir
    dirs <- filterM (isDirectoryInDir dir) contents
    files <- filterM (isFileInDir dir) contents
    return (files, dirs)

isDirectoryInDir :: FilePath -> FilePath -> IO Bool
isDirectoryInDir dir = Dir.withCurrentDirectory dir . Dir.doesDirectoryExist

isFileInDir :: FilePath -> FilePath -> IO Bool
isFileInDir dir = Dir.withCurrentDirectory dir . Dir.doesFileExist
