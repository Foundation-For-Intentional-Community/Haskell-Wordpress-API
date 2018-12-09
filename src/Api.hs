{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE TypeOperators #-}
module Api
    ( Config(..)
    , app
    )
where

import           Control.Monad.Reader           ( ReaderT
                                                , runReaderT
                                                , asks
                                                )
import           Data.Aeson                     ( ToJSON )
import           Data.Pool                      ( Pool
                                                , withResource
                                                )
import           Data.Proxy                     ( Proxy(..) )
import           Data.Text                      ( Text )
import           Database.Persist.Sql           ( (==.)
                                                , SqlBackend
                                                , Entity(..)
                                                , selectList
                                                , fromSqlKey
                                                )
--import           Data.Time                      ( UTCTime )
import           GHC.Generics                   ( Generic )
import           Network.Wai                    ( Application )
import           Servant                        ( (:>)
                                                , Get
                                                , Handler
                                                , JSON
                                                , Server
                                                , ServerT
                                                , serve
                                                , hoistServer
                                                )

import           Schema

app :: Config -> Application
app c = serve api $ server c

server :: Config -> Server API
server c = hoistServer api (`runReaderT` c) routes

api :: Proxy API
api = Proxy

type API =
    "directory" :>
        "entries" :> Get '[JSON] [CommunityListing]

routes :: ServerT API AppM
routes = getListings

type AppM = ReaderT Config Handler
newtype Config = Config { dbPool :: Pool SqlBackend }

runDB :: ReaderT SqlBackend AppM a -> AppM a
runDB m = do
    pool <- asks dbPool
    withResource pool $ runReaderT m

data CommunityListing
    = CommunityListing
        { listingId :: Int
        , name :: Text
        -- TODO: Add these
        --, slug :: Text
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

getListings :: AppM [CommunityListing]
getListings =
    map
            (\(Entity lId l) -> CommunityListing
                (fromIntegral $ fromSqlKey lId)
                (formItemName l)
            )
        <$> runDB (selectList [FormItemForm ==. 2] [])
