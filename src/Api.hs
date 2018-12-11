{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{- | This module specifies the API types/routes & exports a Wai
Application to serve it.
-}
module Api
    ( Config(..)
    , app
    )
where

import           Control.Monad.Reader           ( runReaderT )
import           Data.Aeson                     ( ToJSON )
import           Data.Maybe                     ( fromMaybe )
import           Data.Proxy                     ( Proxy(..) )
import           Data.Text                      ( Text )
import           Database.Persist.Sql           ( (==.)
                                                , Entity(..)
                                                , selectList
                                                , selectFirst
                                                , fromSqlKey
                                                )
import           Flow
import           GHC.Generics                   ( Generic )
import           Network.Wai                    ( Application
                                                , Request
                                                )
import           Servant                        ( (:>)
                                                , (:<|>)(..)
                                                , AuthProtect
                                                , Get
                                                , JSON
                                                , Server
                                                , ServerT
                                                , Context(..)
                                                , serveWithContext
                                                , hoistServerWithContext
                                                )
import           Servant.Server.Experimental.Auth
                                                ( AuthHandler )

import           Schema
import           Types
import           WordpressAuth


-- | Create an API Server with the Given Configuration.
app :: Config -> Application
app c = serveWithContext api (serverContext c) (server c)

server :: Config -> Server API
server c = hoistServerWithContext api context (`runReaderT` c) routes

serverContext :: Config -> Context (AuthHandler Request WordpressUserId ': '[])
serverContext config = authHandler (wordpressConfig config) :. EmptyContext

wordpressConfig :: Config -> WordpressAuthConfig
wordpressConfig c = WordpressAuthConfig
    { cookieName   = defaultCookieName $ wpSiteUrl c
    , getUserData  = fetchUserData
    , loggedInKey  = wpLoggedInKey c
    , loggedInSalt = wpLoggedInSalt c
    }
  where
    fetchUserData userName = flip runReaderT c $ do
        maybeUser <- runDB $ selectFirst [UserLogin ==. userName] []
        case maybeUser of
            Just e  -> Just <$> getSessionTokens e
            Nothing -> return Nothing
    getSessionTokens (Entity userId user) = do
        tokenMeta <- runDB $ selectFirst
            [UserMetaUser ==. userId, UserMetaKey ==. "session_tokens"]
            []
        return
            ( fromIntegral $ fromSqlKey userId
            , userPassword user
            , maybe [] metaToTokenList tokenMeta
            )
      where
        metaToTokenList =
            entityVal .> userMetaValue .> fromMaybe "" .> decodeSessionTokens


context :: Proxy '[AuthHandler Request WordpressUserId]
context = Proxy



api :: Proxy API
api = Proxy

-- brittany-disable-next-binding
type API =
         "directory" :> "entries"
                     :> Get '[JSON] [CommunityListing]
    :<|> "private" :> AuthProtect "wordpress"
                   :> Get '[JSON] [CommunityListing]

routes :: ServerT API AppM
routes = getListings :<|> const getListings

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
