module Main where

import Lib
import Options.Applicative
import Types

import Data.String

data Exec
    = EC Create
    | EM Modify
    | ER Remove
    | EG Get
    deriving (Eq, Ord, Show, Read)

data Create
    = CreatePGMUser Username
                    Password
    | CreateServiceRandom Username
                          Password
                          Service
                          Username
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

data Get
    = Users
    | Services Username
               Password
    | GetServiceData Username
                     Password
                     Service
    | GetAllServiceData Username
                        Password
    | GetServicePassword Username
                         Password
                         Service
    | GetServiceUsername Username
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
    p <- execParser $ parserInfo createParser
    case p of
        EC (CreatePGMUser usr pwd) -> createUser usr pwd
        EC (CreateServiceRandom usr pwd srv srvUsr) ->
            addServiceRandomPassword usr pwd srv srvUsr
        EC (CreateServiceManual usr pwd srv srvUsr srvPwd) ->
            addServiceManualPassword usr pwd srv srvUsr srvPwd
        EM (ModifyPGMPassword usr old new) -> changePgmPassword usr old new
        EM (ModifyPGMUsername old pwd new) -> changePgmUsername old pwd new
        EM (ModifyServiceUsername usr pwd srv new) ->
            changeServiceUsername usr pwd srv new
        EM (ModifyServicePasswordManual usr pwd srv new) ->
            changeServicePasswordManual usr pwd srv new
        EM (ModifyServicePasswordRandom usr pwd srv) ->
            changeServicePasswordRandom usr pwd srv
        ER (RemovePGMUser usr pwd) -> removeUser usr pwd
        ER (RemoveService usr pwd srv) -> removeService usr pwd srv
        EG Users -> getAndPrint users
        EG (Services usr pwd) -> printServices usr pwd
        EG (GetServiceData usr pwd srv) -> printServiceData usr pwd srv
        EG (GetAllServiceData usr pwd) -> printAllServiceData usr pwd
        EG (GetServicePassword usr pwd srv) -> printServicePassword usr pwd srv
        EG (GetServiceUsername usr pwd srv) -> printServiceUsername usr pwd srv
  where
    parserInfo p = info p fullDesc
    getAndPrint get = do
        x <- get
        print x

-- Ultimate program parser
pgmParser :: Parser Exec
pgmParser = createParser <|> modifyParser <|> removeParser <|> getParser

-- TODO: subparsers
-- Create parser
createParser :: Parser Exec
createParser = EC <$> (createServiceParser <|> createPgmUserParser)

createPgmUserParser :: Parser Create
createPgmUserParser = CreatePGMUser <$> pgmUsernameParser <*> pgmPasswordParser

createServiceParser :: Parser Create
createServiceParser = createServiceRandomParser <|> createServiceManualParser

createServiceRandomParser :: Parser Create
createServiceRandomParser =
    CreateServiceRandom <$> pgmUsernameParser <*> pgmPasswordParser <*>
    serviceNameParser <*>
    serviceUsernameParser

createServiceManualParser :: Parser Create
createServiceManualParser =
    CreateServiceManual <$> pgmUsernameParser <*> pgmPasswordParser <*>
    serviceNameParser <*>
    serviceUsernameParser <*>
    servicePasswordParser

-- Modify parser
modifyParser :: Parser Exec
modifyParser = EM <$> undefined

-- Remove parser
removeParser :: Parser Exec
removeParser = ER <$> undefined

-- Get parser
getParser :: Parser Exec
getParser = EG <$> undefined

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
