module Main where

import Control.Monad (replicateM_)
import Data.Char (toLower)
import qualified Data.List as List
import Data.List (sort)
import Lib
import Test.Hspec
import qualified Test.QuickCheck as QC
import Types

genPrintableASCII :: QC.Gen Char
genPrintableASCII = QC.choose (' ', '~')

genUser :: QC.Gen Username
genUser = do
    len <- QC.choose (1, 30)
    QC.vectorOf len $ genPrintableASCII `QC.suchThat` (/= '/')

generateUser :: IO Username
generateUser = QC.generate genUser

genService :: QC.Gen Service
genService = genUser

generateService :: IO Service
generateService = QC.generate genService

genPwd :: QC.Gen Password
genPwd = do
    len <- QC.choose (8, 30)
    QC.vectorOf len genPrintableASCII

generatePwd :: IO Password
generatePwd = QC.generate genPwd

generateService' :: Username -> Password -> IO ()
generateService' usr pwd = do
    srv <- generateService
    susr <- generateUser
    addServiceRandomPassword usr pwd srv susr

generateServices :: Username -> Password -> IO ()
generateServices usr pwd = do
    n <- QC.generate $ QC.choose (1, 10)
    replicateM_ n $ generateService' usr pwd

main :: IO ()
main = do
    testUsr <- ("test" ++) <$> generateUser
    testPwd <- generatePwd
    createUser testUsr testPwd
    generateServices testUsr testPwd
    testSrvs <- unsafeGetAllServiceData testUsr testPwd
    hspec $ do
        describe "Create/remove user" $
            it "Creates/removes the correct user" $
            QC.ioProperty $ do
                usr <- generateUser
                pwd <- generatePwd
                u <- users
                createUser usr pwd
                u' <- users
                removeUser usr pwd
                return $ usr `elem` u' && List.delete usr u' == u
        describe "Add/remove services" $
            it "Correctly adds/removes a service" $
            QC.ioProperty $ do
                srvs <- unsafeServices testUsr testPwd
                susr <- generateUser
                srv <- generateService
                addServiceRandomPassword testUsr testPwd srv susr
                srvs' <- unsafeServices testUsr testPwd
                removeService testUsr testPwd srv
                srvs'' <- unsafeServices testUsr testPwd
                let srv' = map toLower srv
                return $ srvs == srvs'' && sort (srv' : srvs) == srvs'
        describe "Changing passwords" $ do
            it "Service password: should not change other service data" $
                QC.ioProperty $ do
                    srvs <- unsafeServices testUsr testPwd
                    srv <- QC.generate $ QC.elements srvs
                    (srvName, susr, spwd) <-
                        unsafeGetServiceData testUsr testPwd srv
                    changeServicePasswordRandom testUsr testPwd srv
                    (srvName', susr', spwd') <-
                        unsafeGetServiceData testUsr testPwd srv
                    return $
                        srvName == srvName' && susr == susr' && spwd /= spwd'
            it "PGM password" $
            -- TODO: why is this failing some times and passing others
                QC.ioProperty $
                    -- change PGM password
                 do
                    newPwd <- generatePwd
                    unsafeChangePgmPassword testUsr testPwd newPwd
                    let dropPwd (s, u, _) = (s, u)
                    srvs <- unsafeGetAllServiceData testUsr newPwd
                    -- change back to original password
                    unsafeChangePgmPassword testUsr newPwd testPwd
                    -- check all service data has been re-encrypted properly
                    return $ map dropPwd srvs == map dropPwd testSrvs
        describe "Changing usernames" $ do
            it "Service username: should not change other service data" $
                QC.ioProperty $ do
                    srvs <- unsafeServices testUsr testPwd
                    srv <- QC.generate $ QC.elements srvs
                    (srvName, _, spwd) <-
                        unsafeGetServiceData testUsr testPwd srv
                    susr <- generateUser
                    changeServiceUsername testUsr testPwd srv susr
                    (srvName', susr', spwd') <-
                        unsafeGetServiceData testUsr testPwd srv
                    return $
                        srvName == srvName' && susr == susr' && spwd == spwd'
            it "PGM username" $
                QC.ioProperty $
                    -- change PGM username
                 do
                    newUsr <- generateUser
                    changePgmUsername testUsr testPwd newUsr
                    -- change back to original
                    changePgmUsername newUsr testPwd testUsr
                    return True
    removeUser testUsr testPwd
