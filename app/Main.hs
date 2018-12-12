{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
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

import qualified Data.Text                     as T


-- TODO: read config file instead of env var
main :: IO ()
main = do
    dbPass <- getEnv "DB_PASS"
    let dbInfo = defaultConnectInfo { connectDatabase = "fic_wp"
                                    , connectPassword = dbPass
                                    }
    wpSiteUrl      <- textEnv "SITE_URL"
    wpLoggedInKey  <- textEnv "LOGGED_IN_KEY"
    wpLoggedInSalt <- textEnv "LOGGED_IN_SALT"
    wpNonceKey     <- textEnv "NONCE_KEY"
    wpNonceSalt    <- textEnv "NONCE_SALT"
    runStderrLoggingT $ withMySQLPool dbInfo 20 $ \dbPool ->
        liftIO <. runSettings settings <| app Config { .. }
  where
    settings = defaultSettings |> setPort 8080 |> setHost "*"
    textEnv  = fmap T.pack . getEnv
