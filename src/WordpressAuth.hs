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


TODO: Handle validation of anonymous nonces where there's  no cookie.
      Maybe bring back UserData type as union of authed/anonymous with
      userdata on auth branch only.
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

import           Control.Applicative            ( (<|>) )
import           Control.Monad                  ( (<=<)
                                                , unless
                                                , join
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
import           Data.Ratio                     ( (%) )
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
                                                , queryString
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
        , nonceKey :: Text
        -- ^ The NONCE_KEY from wp-config.php
        , nonceSalt :: Text
        -- ^ The NONCE_SALT from wp-config.php
        , getUserData :: Text -> Handler (Maybe (a, Integer, Text, [(Text, POSIXTime)]))
        -- ^ Function for fetching the User's Data, ID, Password, & Session
        -- Tokens from the `user_login` in the Cookie.
        , onAuthenticationFailure :: WordpressAuthError -> Handler a
        -- ^ Function to run when authentication validation fails.
        }

-- | Wrap the UserData in a Maybe, returning Nothing on validation failure.
optionalWordpressAuth :: WordpressAuthConfig a -> WordpressAuthConfig (Maybe a)
optionalWordpressAuth wpConfig = wpConfig
    { getUserData             = fmap (fmap (\(w, x, y, z) -> (Just w, x, y, z)))
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
    | NoNonce
    -- ^ The `Request` has no `X-WP-Nonce` header.
    | EmptyNonce
    -- ^ The nonce header was empty.
    | InvalidNonce
    -- ^ The nonce couldn't be validated.


-- | Expect Wordpress's `LOGGED_IN` cookie & `wp_rest` nonce, returning the
-- UserData if they are valid, or throwing a 401 error otherwise.
--
-- The nonce may be passed via the `X-WP-Nonce` header or `_wpnonce` query
-- parameter.
authHandler :: forall a . WordpressAuthConfig a -> AuthHandler Request a
authHandler wpConfig = mkAuthHandler handler
  where
    handler :: Request -> Handler a
    handler req =
        either (onAuthenticationFailure wpConfig) return <=< runExceptT $ do
            let headers = requestHeaders req
            cookieHeader <- lookup "cookie" headers |> liftMaybe NoCookieHeader
            cookieText   <-
                parseCookiesText cookieHeader
                |> lookup (fromCookieName $ cookieName wpConfig)
                |> fmap decodeText
                |> liftMaybe NoCookieMatches
            wpCookie <- parseWordpressCookie cookieText
                |> liftMaybe CookieParsingFailed
            (userData, userId) <- validateWordpressCookie wpConfig wpCookie
            nonce <- (lookup "x-wp-nonce" headers <|> nonceQuery req)
                |> liftMaybe NoNonce
            tick <- liftIO wordpressNonceTick
            let nonceIsValid = validateWordpressNonce wpConfig
                                                      wpCookie
                                                      tick
                                                      userId
                                                      "wp_rest"
                                                      (decodeUtf8 nonce)
            unless nonceIsValid $ throwError InvalidNonce
            return userData
    nonceQuery :: Request -> Maybe B.ByteString
    nonceQuery = queryString .> lookup "_wpnonce" .> join
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
    -> ExceptT WordpressAuthError Handler (a, Integer)
validateWordpressCookie wpConfig wpCookie = do
    currentTime <- liftIO getPOSIXTime
    if currentTime > expiration wpCookie
        then throwError CookieExpired
        else (username wpCookie |> getUserData wpConfig .> lift) >>= \case
            Nothing -> throwError UserDataNotFound
            Just (userData, userId, userPass, sessionTokens) -> do
                let validHash = validateHash wpConfig wpCookie userPass
                    validSessionToken =
                        validateSessionToken currentTime wpCookie sessionTokens
                unless validHash $ throwError InvalidHash
                unless validSessionToken $ throwError InvalidToken
                return (userData, userId)

-- | Ensure the Cookie's hash matches the salted & hashed password & token.
validateHash :: WordpressAuthConfig a -> WPCookie -> Text -> Bool
validateHash wpConfig wpCookie userPass =
    let passFragment = T.drop 8 userPass |> T.take 4
        key =
                joinHashParts
                        [ username wpCookie
                        , passFragment
                        , posixText $ expiration wpCookie
                        , token wpCookie
                        ]
                    |> wordpressHash wpConfig LoggedInScheme
        hash =
                joinHashParts
                        [ username wpCookie
                        , posixText $ expiration wpCookie
                        , token wpCookie
                        ]
                    |> hmacText SHA256.hmac key
    in  hash == hmac wpCookie
  where
    posixText :: POSIXTime -> Text
    posixText t = T.pack $ show (floor t :: Integer)

-- | Determine if the SHA256 hash of the Cookie's token matches one of the
-- User's unexpired session tokens.
validateSessionToken :: POSIXTime -> WPCookie -> [(Text, POSIXTime)] -> Bool
validateSessionToken currentTime wpCookie sessionTokens =
    let hashedCookieToken = hashText SHA256.hash $ token wpCookie
    in  filter (\(_, expiration) -> expiration >= currentTime) sessionTokens
            |> lookup hashedCookieToken
            |> isJust

-- | Determine if the hash of the tick & token matches the current or
-- previous ticks' hash.
validateWordpressNonce
    :: WordpressAuthConfig a
    -> WPCookie
    -> Integer
    -> Integer
    -> Text
    -> Text
    -> Bool
validateWordpressNonce wpConfig cookie tick userId action nonce =
    let
        thisCycleHash =
            joinHashParts
                    [ T.pack $ show tick
                    , action
                    , T.pack $ show userId
                    , token cookie
                    ]
                |> hashAndTrim
        lastCycleHash =
            joinHashParts
                    [ T.pack $ show $ tick - 1
                    , action
                    , T.pack $ show userId
                    , token cookie
                    ]
                |> hashAndTrim
    in
        nonce /= "" && nonce `elem` [thisCycleHash, lastCycleHash]
  where
    hashAndTrim s =
        let hashed = wordpressHash wpConfig NonceScheme s
        in  T.drop (T.length hashed - 12) hashed |> T.take 10

data AuthScheme
    = LoggedInScheme
    | NonceScheme

-- | Port of wp_hash function. The returned Text is a hex representation of
-- an MD5 HMAC with loggedInKey & loggedInSalt.
wordpressHash :: WordpressAuthConfig a -> AuthScheme -> Text -> Text
wordpressHash wpConfig authScheme textToHash =
    let salt = wordpressSalt wpConfig authScheme
    in  hmacText MD5.hmac salt textToHash

-- | Port of wp_salt function. Builds the salt for the logged_in auth
-- scheme by concatenating the key & salt.
wordpressSalt :: WordpressAuthConfig a -> AuthScheme -> Text
wordpressSalt WordpressAuthConfig {..} = \case
    LoggedInScheme -> loggedInKey <> loggedInSalt
    NonceScheme    -> nonceKey <> nonceSalt

-- | Port of wp_nonce_tick.
wordpressNonceTick :: IO Integer
wordpressNonceTick = do
    let nonceLifetime = 60 * 60 * 24 :: Integer        -- TODO: Pull into config
    time <- getPOSIXTime
    return $ ceiling $ fromInteger (floor time) / (nonceLifetime % 2)

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

-- | Join the different text to hash together by `|` like Wordpress
-- expects.
joinHashParts :: [Text] -> Text
joinHashParts = T.intercalate "|"


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
