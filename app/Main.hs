{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Monad.IO.Class         ( liftIO )
import           Control.Monad.Logger           ( runStderrLoggingT )
import           Database.Persist.MySQL         ( ConnectInfo(..)
                                                , withMySQLPool
                                                , defaultConnectInfo
                                                )
import           Flow
import           Network.Wai.Handler.Warp       ( runSettings
                                                , defaultSettings
                                                , setPort
                                                , setHost
                                                )
import           System.Environment             ( getEnv )

import           Api                            ( Config(..)
                                                , app
                                                )

main :: IO ()
main = do
    dbPass <- getEnv "DB_PASS"
    let dbInfo = defaultConnectInfo { connectDatabase = "fic_wp"
                                    , connectPassword = dbPass
                                    }
    runStderrLoggingT $ withMySQLPool dbInfo 20 $ \pool ->
        liftIO $ runSettings settings <. app <| Config pool
    where settings = defaultSettings |> setPort 8080 |> setHost "*"
