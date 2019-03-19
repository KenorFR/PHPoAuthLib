<?php


namespace OAuth\OAuth2\Service;

use OAuth\Common\Token\Exception\ExpiredTokenException;
use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\OAuth2\Token\TokenInterface;

/**
 * GettyImages service.
 * https://api.gettyimages.com/swagger/ui/index#!/OAuth/ImplicitGrant_Get
 * http://developers.gettyimages.com/api/api-overview.html#client-credentials-flow
 * https://developer.gettyimages.com/apps/mykeys
 */
class GettyImages extends AbstractService
{
    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://api.gettyimages.com/v3/');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationUri(array $additionalParameters = array())
    {
        $parameters = array_merge(
            $additionalParameters,
            array(
                'response_type'      => 'token',
                'client_id'     => $this->credentials->getConsumerId(),
                'redirect_uri'  => $this->credentials->getCallbackUrl(),
            )
        );

        $parameters['scope'] = implode(' ', $this->scopes);

        // Build the url
        $url = clone $this->getAuthorizationEndpoint();
        foreach ($parameters as $key => $val) {
            $url->addToQuery($key, $val);
        }

        return $url;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://api.gettyimages.com/oauth2/auth');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://api.gettyimages.com/oauth2/token');
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    public function recordAccessToken($datas)
    {
        if ($datas['expires_in'] == 31536000) {
            // le token dure 1 an, mais pour acheter, il ne dure que 30 jours, on force à 25 jours
            $datas['expires_in'] = 2160000;
        }
        
        $token = $this->parseAccessTokenResponse(json_encode($datas));
        $token->setLifetime($datas['expires_in']);
        $this->storage->storeAccessToken($this->service(), $token);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token']);

        $token->setExtraParams($data);

        return $token;
    }

    protected function getExtraApiHeaders()
    {
        return [
            'Api-Key' => $this->credentials->getConsumerId(),
            'Accept-Language' => 'fr'
        ];
    }
}
