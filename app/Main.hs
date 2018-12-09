{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Flow                           ( (|>) )
import           Network.Wai.Handler.Warp       ( runSettings
                                                , defaultSettings
                                                , setPort
                                                , setHost
                                                )

import           Api                            ( app )

main :: IO ()
main = runSettings settings app
    where settings = defaultSettings |> setPort 8080 |> setHost "*"
