{-# LANGUAGE DataKinds #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}
{- | This module presents a Servant AuthHandler that validates a LOGGED_IN
Wordpress Cookie.

It validates the token hash using the server-side key & salt values, as
well as the User's session Token.

In order to use this, you must build a `WordpressAuthConfig`, which defines
your cookie name, auth key/salt, and a function to fetch the Password Hash,
Session Tokens, & other data for a User via their `user_login` field.

Upon successful authentication, the other data will be returned. Typically
this would be your User type or the User's ID.

You must define the create `ServerData` type instance yourself:

> type instance AuthServerData (AuthProtect "wp") = Entity User


TODO: Validate the REST nonce as well
        - how to handle anonymous case? No cookie, but nonce.
          Maybe bring back UserData type as union of authed/anonymous with
          userdata on auth branch only
TODO: Implement `auth` & `auth_sec` schemes for wp-admin? Both the
      logged_in & auth/auth_sec cookies are sent in admin requests. Do
      admin routes check both or something? Ask in #wordpress? Preliminary
      tests say requests to `wp-json` just get `logged_in`.
TODO: Allow dynamic generation of CookieName by replacing WPConfig field w/
      `IO CookieName` or `Handler CookieName`. This would allow querying
      the database for the siteurl instead of hardcoding it.
TODO: Move to 2 libraries, splitting off servant specifics. Support both Wai
      Request & Network.HTTP Request types via typeclass?
-}
module WordpressAuth
    ( WordpressAuthConfig(..)
    , optionalWordpressAuth
    , WordpressAuthError(..)
    , authHandler
    , CookieName(..)
    , defaultCookieName
    , decodeSessionTokens
    )
where

import           Control.Monad                  ( (<=<)
                                                , unless
                                                )
import           Control.Monad.Except           ( MonadError
                                                , ExceptT
                                                , runExceptT
                                                , throwError
                                                , liftEither
                                                , lift
                                                )
import           Control.Monad.Reader           ( liftIO )
import           Data.Maybe                     ( mapMaybe
                                                , isJust
                                                )
import           Data.PHPSession                ( PHPSessionValue(..)
                                                , decodePHPSessionValue
                                                )
import           Data.Text                      ( Text )
import           Data.Text.Encoding             ( encodeUtf8
                                                , decodeUtf8
                                                )
import           Data.Time.Clock.POSIX          ( POSIXTime
                                                , getPOSIXTime
                                                )
import           Flow
import           Network.URI.Encode             ( decodeText )
import           Network.Wai                    ( Request
                                                , requestHeaders
                                                )
import           Servant                        ( Handler )
import           Servant.Server.Experimental.Auth
                                                ( AuthHandler
                                                , mkAuthHandler
                                                )
import           Text.Read                      ( readMaybe )
import           Web.Cookie                     ( parseCookiesText )

import qualified Crypto.Hash.MD5               as MD5
import qualified Crypto.Hash.SHA256            as SHA256
import qualified Data.ByteString               as B
import qualified Data.ByteString.Base16        as Base16
import qualified Data.ByteString.Lazy          as LBS
import qualified Data.Text                     as T


-- | The Configuration Options for the Authentication Validation
data WordpressAuthConfig a
    = WordpressAuthConfig
        { cookieName :: CookieName
        -- ^ The Name of the Cookie to check
        , loggedInKey :: Text
        -- ^ The LOGGED_IN_KEY from wp-config.php
        , loggedInSalt :: Text
        -- ^ The LOGGED_IN_SALT from wp-config.php
        , getUserData :: Text -> Handler (Maybe (a, Text, [(Text, POSIXTime)]))
        -- ^ Function for fetching the User's Data, Password, & Session
        -- Tokens from the `user_login` in the Cookie.
        , onAuthenticationFailure :: WordpressAuthError -> Handler a
        -- ^ Function to run when authentication validation fails.
        }

-- | Wrap the UserData in a Maybe, returning Nothing on validation failure.
optionalWordpressAuth :: WordpressAuthConfig a -> WordpressAuthConfig (Maybe a)
optionalWordpressAuth wpConfig = wpConfig
    { getUserData             = fmap (fmap (\(x, y, z) -> (Just x, y, z)))
                                    . getUserData wpConfig
    , onAuthenticationFailure = const (return Nothing)
    }

-- | Potential errors that may occur during authentication.
data WordpressAuthError
    = NoCookieHeader
    -- ^ The `Request` has no `Cookie` header.
    | NoCookieMatches
    -- ^ No Cookie matched the expected `CookieName`.
    | CookieParsingFailed
    -- ^ We couldn't decode the Cookie's text.
    | CookieExpired
    -- ^ The expiration time of the Cookie is in the past.
    | UserDataNotFound
    -- ^ The getUserData function returned Nothing.
    | InvalidHash
    -- ^ The HMAC hash in the Cookie couldn't be validated.
    | InvalidToken
    -- ^ The session token in the Cookie couldn't be validated.


-- | Expect Wordpress's `LOGGED_IN_COOKIE`, returning the UserData if it is
-- valid, or throwing a 401 error otherwise.
authHandler :: forall a . WordpressAuthConfig a -> AuthHandler Request a
authHandler wpConfig = mkAuthHandler handler
  where
    handler :: Request -> Handler a
    handler req =
        either (onAuthenticationFailure wpConfig) return <=< runExceptT $ do
            cookieHeader <- lookup "cookie" (requestHeaders req)
                |> liftMaybe NoCookieHeader
            cookieText <-
                parseCookiesText cookieHeader
                |> lookup (fromCookieName $ cookieName wpConfig)
                |> fmap decodeText
                |> liftMaybe NoCookieMatches
            wpCookie <- parseWordpressCookie cookieText
                |> liftMaybe CookieParsingFailed
            validateWordpressCookie wpConfig wpCookie
    liftMaybe :: MonadError e m => e -> Maybe x -> m x
    liftMaybe a = liftEither . maybeToEither a
    maybeToEither :: e -> Maybe x -> Either e x
    maybeToEither e = maybe (Left e) Right


-- Parsing / Validation

data WPCookie
    = WPCookie
        { username :: Text
        , expiration :: POSIXTime
        , token :: Text
        , hmac :: Text
        }
    deriving (Show)

-- | Parse the Cookie content into a `WPCookie`.
parseWordpressCookie :: Text -> Maybe WPCookie
parseWordpressCookie rawCookie = case T.splitOn "|" rawCookie of
    [username, expiration_, token, hmac] ->
        case fromInteger <$> readMaybe (T.unpack expiration_) of
            Just expiration -> Just WPCookie { .. }
            Nothing         -> Nothing
    _ -> Nothing

-- | Validate the Hash & Token in the Cookie, returning the User Data or
-- throwing a WordpressAutherror.
validateWordpressCookie
    :: WordpressAuthConfig a
    -> WPCookie
    -> ExceptT WordpressAuthError Handler a
validateWordpressCookie wpConfig wpCookie = do
    currentTime <- liftIO getPOSIXTime
    if currentTime > expiration wpCookie
        then throwError CookieExpired
        else (username wpCookie |> getUserData wpConfig .> lift) >>= \case
            Nothing -> throwError UserDataNotFound
            Just (userData, userPass, sessionTokens) -> do
                let validHash = validateHash wpConfig wpCookie userPass
                    validSessionToken =
                        validateSessionToken currentTime wpCookie sessionTokens
                unless validHash $ throwError InvalidHash
                unless validSessionToken $ throwError InvalidToken
                return userData

-- | Ensure the Cookie's hash matches the salted & hashed password & token.
validateHash :: WordpressAuthConfig a -> WPCookie -> Text -> Bool
validateHash wpConfig wpCookie userPass =
    let passFragment = T.drop 8 userPass |> T.take 4
        key =
                T.intercalate
                        "|"
                        [ username wpCookie
                        , passFragment
                        , posixText $ expiration wpCookie
                        , token wpCookie
                        ]
                    |> wordpressHash wpConfig
        hash =
                T.intercalate
                        "|"
                        [ username wpCookie
                        , posixText $ expiration wpCookie
                        , token wpCookie
                        ]
                    |> hmacText SHA256.hmac key
    in  hash == hmac wpCookie
  where
    posixText :: POSIXTime -> Text
    posixText t = T.pack $ show (floor t :: Integer)

-- Ensure the SHA256 hash of the Cookie's token matches one of the User's
-- unexpired session tokens.
validateSessionToken :: POSIXTime -> WPCookie -> [(Text, POSIXTime)] -> Bool
validateSessionToken currentTime wpCookie sessionTokens =
    let hashedCookieToken = hashText SHA256.hash $ token wpCookie
    in  filter (\(_, expiration) -> expiration >= currentTime) sessionTokens
            |> lookup hashedCookieToken
            |> isJust

-- | Port of wp_hash function. The returned Text is a hex representation of
-- an MD5 HMAC with loggedInKey & loggedInSalt.
wordpressHash :: WordpressAuthConfig a -> Text -> Text
wordpressHash wpConfig textToHash =
    let salt = wordpressSalt wpConfig in hmacText MD5.hmac salt textToHash

-- | Port of wp_salt function. Builds the salt for the logged_in auth
-- scheme by concatenating the key & salt.
wordpressSalt :: WordpressAuthConfig a -> Text
wordpressSalt WordpressAuthConfig { loggedInKey, loggedInSalt } =
    loggedInKey <> loggedInSalt

-- | Decode a serialized array containing a User's Session Tokens, usually
-- stored as the `session_tokens` usermeta.
--
-- It may be an associative array of tokens to expiration times, or tokens
-- to an associative array of sub-fields.
decodeSessionTokens :: Text -> [(Text, POSIXTime)]
decodeSessionTokens serializedText =
    case decodePHPSessionValue (LBS.fromStrict $ encodeUtf8 serializedText) of
        Nothing       -> []
        Just phpValue -> decodeTokenArray phpValue
  where
    decodeTokenArray = \case
        PHPSessionValueArray sessionTokens ->
            mapMaybe decodeToken sessionTokens
        _ -> []
    -- Decode a single Token, which can be a (token, expiration) pair, or
    -- an associative array.
    decodeToken = \case
        (PHPSessionValueString token, PHPSessionValueInt expiration) ->
            Just
                ( decodeUtf8 $ LBS.toStrict token
                , fromInteger $ fromIntegral expiration
                )
        (PHPSessionValueString token, PHPSessionValueArray tokenData) ->
            (decodeUtf8 $ LBS.toStrict token, ) <$> decodeTokenData tokenData
        _ -> Nothing
    -- Decode the sub-fields of a Token.
    decodeTokenData = \case
        [] -> Nothing
        (PHPSessionValueString "expiration", PHPSessionValueInt expiration) : _
            -> Just $ fromInteger $ fromIntegral expiration
        _ : rest -> decodeTokenData rest

-- | Apply an HMAC hashing function to Text values.
hmacText
    :: (B.ByteString -> B.ByteString -> B.ByteString) -> Text -> Text -> Text
hmacText hasher key =
    encodeUtf8 .> hasher (encodeUtf8 key) .> Base16.encode .> decodeUtf8

-- | Apply a hashing function to Text values.
hashText :: (B.ByteString -> B.ByteString) -> Text -> Text
hashText hasher = encodeUtf8 .> hasher .> Base16.encode .> decodeUtf8


-- Auth Configuration

-- | Represents the name of Wordpress's `LOGGED_IN` Cookie.
data CookieName
    = CustomCookieName Text
    -- ^ Use the fixed name for the Cookie.
    | CookieNameWithMD5 Text Text
    -- ^ Use the given name with the MD5 of some other text appended to it.

-- | Build the text for a CookieName.
fromCookieName :: CookieName -> Text
fromCookieName = \case
    CustomCookieName n                -> n
    CookieNameWithMD5 name textToHash -> name <> hashText MD5.hash textToHash


-- | The default Cookie name for Wordpress, it consists of
-- `wordpress_logged_in_` with the MD5 hash of the Site URL appended to it.
defaultCookieName :: Text -> CookieName
defaultCookieName = CookieNameWithMD5 "wordpress_logged_in_"
