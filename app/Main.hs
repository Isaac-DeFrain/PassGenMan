{-# OPTIONS_GHC -fno-warn-orphans #-}

module Main where

import Lib
import Options.Applicative
import Types

import Data.String

data Exec
    = EC Create
    | EM Modify
    | ER Remove
    deriving (Eq, Ord, Show, Read)

data Create
    = CreatePGMUser Username
                    Password
    | CreateServiceRandom Username
                          Password
                          Service
                          Username
                          Int
    | CreateServiceManual Username
                          Password
                          Service
                          Username
                          Password
    deriving (Eq, Ord, Show, Read)

data Modify
    = ModifyPGMPassword Username
                        Password
                        Password
    | ModifyPGMUsername Username
                        Password
                        Username
    | ModifyServicePasswordManual Username
                                  Password
                                  Service
                                  Password
    | ModifyServicePasswordRandom Username
                                  Password
                                  Service
                                  Int
    | ModifyServiceUsername Username
                            Password
                            Service
                            Username
    deriving (Eq, Ord, Show, Read)

data Remove
    = RemovePGMUser Username
                    Password
    | RemoveService Username
                    Password
                    Service
    deriving (Eq, Ord, Show, Read)

instance Data.String.IsString Create where
    fromString = read

instance Data.String.IsString Int where
    fromString = read

-- TODO: command line parsing
main :: IO ()
main = do
    p <- execParser $ parserInfo createAlt
    case p of
        EC (CreatePGMUser usr pwd) -> createUser usr pwd
        EC (CreateServiceRandom usr pwd srv srvUsr n) ->
            addServiceRandomPassword usr pwd srv srvUsr n
        EC (CreateServiceManual usr pwd srv srvUsr srvPwd) ->
            addServiceManualPassword usr pwd srv srvUsr srvPwd
        EM _ -> undefined
        ER _ -> undefined

createAlt :: Parser Exec
createAlt = EC <$> (serviceParser <|> pgmParser)

pgmParser :: Parser Create
pgmParser = CreatePGMUser <$> pgmUsernameParser <*> pgmPasswordParser

serviceParser :: Parser Create
serviceParser = serviceRandomParser <|> serviceManualParser

serviceRandomParser :: Parser Create
serviceRandomParser =
    CreateServiceRandom <$> pgmUsernameParser <*> pgmPasswordParser <*>
    serviceNameParser <*>
    serviceUsernameParser <*>
    servicePasswordLengthParser

serviceManualParser :: Parser Create
serviceManualParser =
    CreateServiceManual <$> pgmUsernameParser <*> pgmPasswordParser <*>
    serviceNameParser <*>
    serviceUsernameParser <*>
    servicePasswordParser

pgmUsernameParser :: Parser Username
pgmUsernameParser =
    strOption (long "user" <> short 'u' <> help "PassGenMan username")

pgmPasswordParser :: Parser Password
pgmPasswordParser =
    strOption (long "pwd" <> short 'p' <> help "PassGenMan password")

serviceNameParser :: Parser Service
serviceNameParser =
    strOption
        (long "service" <> short 's' <> help "Name of service to register")

serviceUsernameParser :: Parser Username
serviceUsernameParser =
    strOption (long "username" <> short 'n' <> help "Service username")

servicePasswordLengthParser :: Parser Int
servicePasswordLengthParser =
    strOption (long "length" <> short 'l' <> help "Length of service password")

servicePasswordParser :: Parser Password
servicePasswordParser =
    strOption (long "password" <> help "Manually choose password")

parserInfo :: Parser a -> ParserInfo a
parserInfo p = info p fullDesc
