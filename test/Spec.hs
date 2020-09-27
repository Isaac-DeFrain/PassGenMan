module Main where

import Test.Hspec

-- import qualified Test.QuickCheck as QC
main :: IO ()
main =
    hspec $ do
        describe "Changing passwords" $ do
            it "Service passwords" $ True `shouldBe` True
            it "PMG password" $ True `shouldBe` True
        describe "Changing usernames" $ do
            it "Service usernames" $ True `shouldBe` True
            it "PMG username" $ True `shouldBe` True
        describe "These are tests for the second property" $ do
            it "Property2 requirement 1" $ True `shouldBe` True
            it "Property2 requirement 2" $ True `shouldBe` True
