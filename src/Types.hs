{- | This module contains the general types used by the server.
-}
module Types where
import           Control.Monad.Reader           ( ReaderT
                                                , runReaderT
                                                , asks
                                                )
import           Data.Pool                      ( Pool
                                                , withResource
                                                )
import           Data.Text                      ( Text )
import           Database.Persist.Sql           ( SqlBackend )
import           Servant                        ( Handler )

-- | A monad representig application routes. It gives route handlers access
-- to a `Config` via a Reader transformer.
type AppM = ReaderT Config Handler

-- | The configuration data used by the Handler routes.
data Config
    = Config
        { dbPool :: Pool SqlBackend
        -- ^ A Pool of sql connections
        , wpSiteUrl :: Text
        -- ^ The `siteurl` option of the Wordpress site.
        , wpLoggedInKey :: Text
        -- ^ The LOGGED_IN_KEY for the Wordpress site.
        , wpLoggedInSalt :: Text
        -- ^ The LOGGED_IN_SALT for the Wordpress site.
        , wpNonceKey :: Text
        -- ^ The NONCE_KEY for the Wordpress site.
        , wpNonceSalt :: Text
        -- ^ The NONCE_SALT for the Wordpress site.
        }

-- | Run a database acton in a route handler.
runDB :: ReaderT SqlBackend AppM a -> AppM a
runDB m = do
    pool <- asks dbPool
    withResource pool $ runReaderT m
