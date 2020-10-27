-- TODO: salt password before hashing
module Lib
    ( users
    , printServices
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
    , printServiceData
    , printServicePassword
    , printServiceUsername
    , printAllServiceData
    , getUserDir
    , sha256
    , separateContentsInDir
    , backUpUser
    , setUserBackupDir
    ) where

import Control.Monad (filterM, replicateM, unless)
import Crypto
import qualified Crypto.Hash as Hash
import qualified Data.ByteString.Char8 as BS
import Data.Char (toLower)
import Data.Either (lefts, rights)
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

-- | print the list of services registered to the given user
printServices :: Username -> Password -> IO ()
printServices usr pwd = do
    srvs' <- services usr pwd
    case srvs' of
        Left err -> putStrLn err
        Right srvs -> putStr $ unlines srvs

-- | list of services registered to the given user
services :: Username -> Password -> IO (Either String [Service])
services usr pwd = do
    verified <- verifyPwd usr pwd
    case verified of
        Left err -> return $ Left err
        Right _ -> do
            usrServices <- getUserServicesDir usr
            Right . sort . map dropDot <$> Dir.listDirectory usrServices
  where
    dropDot = drop 1

-- | create new user directory
createUser :: Username -> Password -> IO ()
createUser usr pwd =
    unless ('/' `elem` usr) $ do
        exists <- doesUserExist usr
        case exists of
            Left _ -> do
                srvDir <- getUserServicesDir usr
                pwdFile <- getUserPwdFilePath usr
                buFile <- getUserBackupFilePath usr
                Dir.createDirectoryIfMissing True srvDir
                Sys.writeFile pwdFile $ hashStr ++ "\n"
                Sys.writeFile buFile ""
                putStrLn $
                    "This glorious day will forever be remembered as the birthday of " ++
                    usr
            Right _ ->
                putStrLn $
                "A doppelganger has been spotted!\n" ++
                usr ++ " already exists!"
  where
    hashStr = sha256 pwd

-- | remove a PassGenMan user
removeUser :: Username -> Password -> IO ()
removeUser usr pwd = do
    verified <- verifyPwd usr pwd
    case verified of
        Left err -> putStrLn $ "Cannot remove " ++ usr ++ ": " ++ err
        Right _ -> do
            usrDir <- getUserDir usr
            Dir.removeDirectoryRecursive usrDir
            putStr $
                unlines
                    [ "You have both the power to create and destroy."
                    , "Today, you chose destruction."
                    , usr ++ " has been oblierated."
                    ]

-- | verify the given username's password
verifyPwd :: Username -> Password -> IO (Either String Affirmative)
verifyPwd usr pwd = do
    exists <- doesUserExist usr
    case exists of
        Left _ -> return $ Left "Invalid username/password!"
        Right _ -> do
            pwdHash' <- getUserPwdHash usr
            return $
                case pwdHash' of
                    Left _ -> Left "Invalid username/password!"
                    Right pwdHash ->
                        if sha256 pwd == pwdHash
                            then Right Y
                            else Left "Invalid username/password!"

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
    case verified of
        Left err -> putStrLn err
        Right _ -> do
            srvFilePath <- getUserServiceFilePath usr srv
            rpwd <- randomPwd len
            encryptUsrPwdAndWrite pwd susr rpwd srvFilePath
            putStrLn $
                concat
                    [ "Congratulations "
                    , usr
                    , ", your "
                    , srv
                    , " username and password have been securely created and stored."
                    ]

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
    case verified of
        Left err -> putStrLn err
        Right _ -> do
            putStrLn "Confirm new password: "
            newPwd <- getLine
            if newPwd == spwd
                then do
                    srvFilePath <- getUserServiceFilePath usr srv
                    encryptUsrPwdAndWrite pwd susr spwd srvFilePath
                    putStrLn $
                        concat
                            [ "Congratulations "
                            , usr
                            , ", your "
                            , srv
                            , " username and password have been securely created and stored."
                            ]
                else putStrLn
                         "Unfortunately, those passwords do not match. Try again."

-- | remove the specified service from the given user
removeService :: Username -> Password -> Service -> IO ()
removeService usr pwd srv = do
    exists <- doesServiceExist usr pwd srv
    case exists of
        Left err -> putStrLn err
        Right _ -> do
            srvFilePath <- getUserServiceFilePath usr srv
            Dir.removeFile srvFilePath

-- | retrieve service username
printServiceUsername :: Username -> Password -> Service -> IO ()
printServiceUsername usr pwd srv = do
    exists <- doesServiceExist usr pwd srv
    case exists of
        Left err -> putStrLn err
        Right _ -> do
            (_, hdl) <- getServicePathReadHdl usr srv
            [encSUsr, _] <- getNlines 2 hdl
            Sys.hClose hdl
            susr <- decrypt pwd encSUsr
            putStrLn $ "Username: " ++ susr

-- | print user's given service password
printServicePassword :: Username -> Password -> Service -> IO ()
printServicePassword usr pwd srv = do
    exists <- doesServiceExist usr pwd srv
    case exists of
        Left err -> putStrLn err
        Right _ -> do
            (_, hdl) <- getServicePathReadHdl usr srv
            [_, encSrvPwd] <- getNlines 2 hdl
            Sys.hClose hdl
            spwd <- decrypt pwd encSrvPwd
            putStrLn $ "Password: " ++ spwd

-- | print requested service data
printServiceData :: Username -> Password -> Service -> IO ()
printServiceData usr pwd srv =
    putStrLn srv >> printServiceUsername usr pwd srv >>
    printServicePassword usr pwd srv >>
    putStrLn ""

-- | retrieve service (name, username, password)
getServiceData ::
       Username
    -> Password
    -> Service
    -> IO (Either String (Service, Username, Password))
getServiceData usr pwd srv = do
    exists <- doesServiceExist usr pwd srv
    case exists of
        Left err -> return $ Left err
        Right _ -> do
            (_, hdl) <- getServicePathReadHdl usr srv
            serviceData <- getNlines 2 hdl
            Sys.hClose hdl
            Right <$> serviceTuple serviceData
  where
    serviceTuple l = do
        susr <- decrypt pwd $ head l
        spwd <- decrypt pwd $ l !! 1
        return (srv, susr, spwd)

printAllServiceData :: Username -> Password -> IO ()
printAllServiceData usr pwd = do
    srvData' <- getAllServiceData usr pwd
    case srvData' of
        Left err -> putStrLn err
        Right srvData -> printAllServiceData' srvData
  where
    printAllServiceData' = mapM_ (\(s, _, _) -> printServiceData usr pwd s)

-- | list all service data registered to given user
getAllServiceData ::
       Username
    -> Password
    -> IO (Either String [(Service, Username, Password)])
getAllServiceData usr pwd = do
    srvs' <- services usr pwd
    case srvs' of
        Left err -> return $ Left err
        Right srvs -> do
            srvData <- mapM (getServiceData usr pwd) srvs
            return $
                case lefts srvData of
                    [] -> Right $ rights srvData
                    err:_ -> Left err

-- | change PassGenMan password
changePgmPassword ::
       Username
    -> Password -- ^ old PGM password
    -> Password -- ^ new PGM password
    -> IO ()
changePgmPassword usr old new = do
    verified <- verifyPwd usr old
    case verified of
        Left err -> putStrLn err
        Right _ -> do
            pwdFilePath <- getUserPwdFilePath usr
            putStrLn "Confirm new password: "
            pwd <- getLine
            if pwd == new
                then do
                    srvs' <- services usr old
                    case srvs' of
                        Left err -> putStrLn err
                        Right srvs -> do
                            Sys.writeFile pwdFilePath $ sha256 new ++ "\n"
                            mapM_ (changeServiceData usr old new) srvs
                else putStrLn "Passwords do not match! Try again."

-- | change PassGenMan username
changePgmUsername ::
       Username -- ^ old PGM username
    -> Password
    -> Username -- ^ new PGM username
    -> IO ()
changePgmUsername usr pwd new = do
    verified <- verifyPwd usr pwd
    case verified of
        Left err -> putStrLn err
        Right _ -> do
            pgmDir <- getPgmDir
            usrDir <- getUserDir usr
            Dir.renameDirectory usrDir $ pgmDir ++ "/." ++ new

-- | pseudorandomly generate new service password
changeServicePasswordRandom ::
       Username -- ^ PassGenMan username
    -> Password -- ^ PassGenMan password
    -> Service
    -> Int -- ^ length of new service password
    -> IO ()
changeServicePasswordRandom usr pwd srv len = do
    exists <- doesServiceExist usr pwd srv
    case exists of
        Left err -> putStrLn err
        Right _ -> do
            (srvFilePath, susr, old) <- getServicePathContents usr pwd srv
            new <- randomPwd len
            writeServiceContents srvFilePath pwd (susr, new)
            putStrLn $
                concat
                    [ "Your old "
                    , srv
                    , " password "
                    , old
                    , " has been changed to "
                    , new
                    ]

-- | manually change service password
changeServicePasswordManual ::
       Username -- ^ PassGenMan username
    -> Password -- ^ PassGenMan password
    -> Service
    -> Password -- ^ new service password
    -> IO ()
changeServicePasswordManual usr pwd srv new =
    if length new < 8
        then putStrLn
                 "For the love of security, your password must conatain at least 8 characters!"
        else do
            exists <- doesServiceExist usr pwd srv
            case exists of
                Left err -> putStrLn err
                Right _ -> do
                    (srvFilePath, susr, old) <-
                        getServicePathContents usr pwd srv
                    putStrLn "Confirm new password: "
                    newPwd <- getLine
                    if newPwd == new
                        then do
                            writeServiceContents srvFilePath pwd (susr, new)
                            putStrLn $
                                concat
                                    [ "Your old "
                                    , srv
                                    , " password "
                                    , old
                                    , " has been changed to "
                                    , new
                                    ]
                        else putStrLn "Passwords do not match! Try again."

getServicePathContents ::
       Username -> Password -> Service -> IO (FilePath, Username, Password)
getServicePathContents usr pwd srv = do
    (srvFilePath, hdl) <- getServicePathReadHdl usr srv
    [encSUsr, encSPwd] <- getNlines 2 hdl
    susr <- decrypt pwd encSUsr
    spwd <- decrypt pwd encSPwd
    Sys.hClose hdl
    return (srvFilePath, susr, spwd)

writeServiceContents :: FilePath -> Password -> (Username, Password) -> IO ()
writeServiceContents srvFilePath pwd (susr, spwd) = do
    hdl <- Sys.openFile srvFilePath Sys.WriteMode
    encSUsr <- encrypt pwd susr
    encSPwd <- encrypt pwd spwd
    Sys.hPutStrLn hdl $ unlines [encSUsr, encSPwd]
    Sys.hClose hdl

-- | pseudorandomly generate new service password
changeServiceUsername ::
       Username -- ^ PassGenMan username
    -> Password -- ^ PassGenMan password
    -> Service
    -> Username -- ^ new service username
    -> IO ()
changeServiceUsername usr pwd srv new = do
    exists <- doesServiceExist usr pwd srv
    case exists of
        Left err -> putStrLn err
        Right _ -> do
            (srvFilePath, hdl) <- getServicePathReadHdl usr srv
            [encSUsr', encSPwd] <- getNlines 2 hdl
            old <- decrypt pwd encSUsr'
            Sys.hClose hdl
            hdl' <- Sys.openFile srvFilePath Sys.WriteMode
            encSUsr <- encrypt pwd new
            Sys.hPutStrLn hdl' $ unlines [encSUsr, encSPwd]
            Sys.hClose hdl'
            putStrLn $
                concat
                    [ "Your old "
                    , srv
                    , " username "
                    , old
                    , " has been changed to "
                    , new
                    ]

-- | changes the encryption password for the given service
changeServiceData :: Username -> Password -> Password -> Service -> IO ()
changeServiceData usr pwd new srv = do
    (srvFilePath, hdl) <- getServicePathReadHdl usr srv
    [encSUsr', encSPwd'] <- getNlines 2 hdl
    susr <- decrypt pwd encSUsr'
    spwd <- decrypt pwd encSPwd'
    Sys.hClose hdl
    Dir.removeFile srvFilePath
    hdl' <- Sys.openFile srvFilePath Sys.WriteMode
    encSUsr <- encrypt new susr
    encSPwd <- encrypt new spwd
    Sys.hPutStrLn hdl' $ unlines [encSUsr, encSPwd]
    Sys.hClose hdl'

----------------------
-- helper functions --
----------------------
sha256 :: Password -> String
sha256 = show . Hash.hashWith Hash.SHA256 . BS.pack

-- | verify existence of user
doesUserExist :: Username -> IO (Either String Affirmative)
doesUserExist usr = do
    res <- elem usr <$> users
    return $
        if res
            then Right Y
            else Left $ "User " ++ usr ++ " does not exist!"

-- | verify existence of service for user
doesServiceExist ::
       Username -> Password -> Service -> IO (Either String Affirmative)
doesServiceExist usr pwd srv = do
    verified <- verifyPwd usr pwd
    case verified of
        Left err -> return $ Left err
        Right _ -> do
            srvs' <- services usr pwd
            case srvs' of
                Left err -> return $ Left err
                Right srvs ->
                    return $
                    if map toLower srv `elem` srvs
                        then Right Y
                        else Left $
                             srv ++ " is not a service registered to " ++ usr

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
getUserPwdHash :: Username -> IO (Either String String)
getUserPwdHash usr = do
    pwdFilePath <- getUserPwdFilePath usr
    exists <- Dir.doesFileExist pwdFilePath
    if exists
        then do
            hdl <- Sys.openFile pwdFilePath Sys.ReadMode
            hash <- Sys.hGetContents hdl
            -- delete '\n' from end
            return . Right $ init hash
        else return $ Left "User does not exist!"

-- | generate random password of given length
randomPwd :: Int -> IO Password
randomPwd n
    | n <= 8 = randomString (onlyPrintable randomASCII) 8
    | otherwise = randomString (onlyPrintable randomASCII) n

-- | user's services directory with handle in read mode
getServicePathReadHdl :: Username -> Service -> IO (FilePath, Sys.Handle)
getServicePathReadHdl usr srv = do
    srvFilePath <- getUserServiceFilePath usr srv
    hdl <- Sys.openFile srvFilePath Sys.ReadMode
    return (srvFilePath, hdl)

-- | get the specified number of lines from the given file handle
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
    case verified of
        Left err -> putStrLn err
        Right _ -> do
            _ <- Dir.createDirectoryIfMissing True buDir
            _ <- Dir.createDirectoryIfMissing True $ buDir ++ "/.services"
            buFile <- getUserBackupFilePath usr
            Sys.writeFile buFile $ buDir ++ "\n"

-- | user backup directory
getUserBackupDir :: Username -> IO (Either String FilePath)
getUserBackupDir usr = do
    buFile <- getUserBackupFilePath usr
    exists <- Dir.doesFileExist buFile
    if exists
        then do
            hdl <- Sys.openFile buFile Sys.ReadMode
            buDir <- Sys.hGetLine hdl
            return $ Right buDir
        else return . Left $ "A backup directory has not been set for " ++ usr

-- | copy user's PGM directory to their backup directory
backUpUser :: Username -> Password -> IO ()
backUpUser usr pwd = do
    verified <- verifyPwd usr pwd
    case verified of
        Left err -> putStrLn err
        Right _ -> do
            res <- getUserBackupDir usr
            case res of
                Left err -> putStrLn err
                Right buDir -> backUpPaths usr buDir

-- | separates files and directories
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

allAbsFilePathsInDir :: FilePath -> IO [FilePath]
allAbsFilePathsInDir dir = do
    (files', dirs) <- separateContentsInDir dir
    files <- mapM (Dir.withCurrentDirectory dir . Dir.makeAbsolute) files'
    rest <- mapM (Dir.withCurrentDirectory dir . allAbsFilePathsInDir) dirs
    return $ files ++ concat rest

backUpPaths :: Username -> FilePath -> IO ()
backUpPaths usr buDir = do
    usrDir <- getUserDir usr
    absPaths <- allAbsFilePathsInDir usrDir
    let prefix = length usrDir
        relPaths = map (drop prefix) absPaths
        buPaths = map (buDir ++) relPaths
        both = zip absPaths buPaths
    mapM_ (uncurry Dir.copyFile) both
