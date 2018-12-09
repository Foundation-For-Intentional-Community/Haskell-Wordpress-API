{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Api where

import           Data.Aeson                     ( ToJSON )
import           Data.Proxy                     ( Proxy(..) )
import           Data.Text                      ( Text )
--import           Data.Time                      ( UTCTime )
import           GHC.Generics                   ( Generic )
import           Network.Wai                    ( Application )
import           Servant                        ( (:>)
                                                , Get
                                                , JSON
                                                , Server
                                                , serve
                                                )

app :: Application
app = serve api routes

type API = "directory" :> "entries" :> Get '[JSON] [CommunityListing]

api :: Proxy API
api = Proxy

routes :: Server API
routes = return listings

data CommunityListing
    = CommunityListing
        { listingId :: Int
        , name :: Text
        , slug :: Text
        --, imageUrl :: Text
        --, thumbnailUrl :: Text
        --, createdAt :: UTCTime
        --, updatedAt :: UTCTime
        --, communityStatus :: Text
        --, city :: Text
        --, state :: Text
        --, country :: Text
        --, openToMembership :: Text
        --, openToVisitors :: Text
        }
        deriving (Eq, Show, Generic)

instance ToJSON CommunityListing

listings :: [CommunityListing]
listings = [CommunityListing 1 "l1" "l2"]
