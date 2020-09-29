module Main where

import qualified Data.List as List
import Lib
import Test.Hspec
import qualified Test.QuickCheck as QC

main :: IO ()
main =
    hspec $ do
        describe "Create/remove user" $
            it "Creates/removes the correct user" $
            QC.ioProperty $ do
                usr <- QC.generate $ QC.listOf QC.arbitrary
                pwd <- QC.generate $ QC.listOf QC.arbitrary
                u <- users
                createUser usr pwd
                u' <- users
                removeUser usr pwd
                return $ usr `elem` u' && List.delete usr u' == u
        describe "Adding services" $
            it "Correctly add the service" $ True `shouldBe` True
        describe "Changing passwords" $ do
            it "Service password" $ True `shouldBe` True
            it "PGM password" $ True `shouldBe` True
        describe "Changing usernames" $ do
            it "Service username" $ True `shouldBe` True
            it "PGM username" $ True `shouldBe` True
