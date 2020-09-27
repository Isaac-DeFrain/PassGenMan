module Main where

import Lib
import Options.Applicative
import Types

data Create
    = CreatePMGUser Username
                    Password
    | CreateService Username
                    Password
                    Service
                    Username
                    (Maybe Password)
    deriving (Eq, Ord, Show, Read)

data Change
    = ChangePMGPassword Username
                        Password
                        Password
    | ChangePMGUsername Username
                        Password
                        Username
    | ChangeServicePassword Username
                            Password
                            Service
                            (Maybe Password)
    | ChangeServiceUsername Username
                            Password
                            Service
                            Username

data Remove
    = RemovePMGUser Username
                    Password
    | RemoveService Username
                    Password
                    Service

-- TODO: command line parsing
main :: IO ()
main = putStrLn "unimplemented"
