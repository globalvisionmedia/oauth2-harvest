# Harvest Provider for OAuth 2.0 Client - For Harvest API V2

Harvest OAuth 2.0 support for the PHP League's OAuth 2.0 Client
With thanks to Nile Suan for the original harvest provider. This package updates it for V2 of the Harvest API

# Installation
    composer require globalvisionmedia/oauth2-harvest

# Obtaining a Harvest access key
1. To get a key you will need to creare an OAuth2 application in the Harvest Developer area: (https://id.getharvest.com/developers)

2. Click the Create new Auth2 application button to create a key

3. Select a name for yoru application

4. The redirect URL must be exactly the same (including the http:// or https://) as the redirectUri below and is the URL of your application. 
   Access - select I need access to one account
   Product - select I want access to Harvest.
5. Note down the Client ID and Client Secret
   
6. You need to know your Account ID on Harvest. This is not shown when you create an OAuth2 app, but if you create a temporary
   "Personal access token" you are shown your Account ID. Note it and then you can delete the temporary personal access token.

# Usage
Usage is the same as The League's OAuth client, using \GlobalVisionMedia\OAuth2\MYOBClient\Provider\MYOB as the provider, except for the following:

1. Harvest requires you to set a User Agent in Guzzle (see Example, below)

2. You need to supply an Account ID to the Harvest API (see above)

3. Harvest's APIs are throttled - the documented limit is 15 calls per 100 seconds (The simplest option is to limit to 6 per second) - see example below


# Instantiation
    $provider = new \GlobalVisionMedia\OAuth2\HarvestClient\Provider\Harvest([
        'clientId'                => 'yourId',          // The Client ID assigned to you by Harvest
        'clientSecret'            => 'yourSecret',      // The Client Secret assigned to you by Harvest
        'redirectUri'             => 'yourRedirectUri'  // The Redirect URL you specified for your app on Harvest
    ]);
    
# Tip (also applies to other providers)
    When you instantiate your provider, you can also pass a second parameter containing a collaborator for your httpClient.
    Doing that means you can define your own Guzzle client and do things such as:
    
      1. Setting Guzzle into debug mode, or
      2. Adding a rate limiter mildeware (composer require spatie/guzzle-rate-limiter-middleware)
      
    
    use GuzzleHttp\Client;
    use GuzzleHttp\HandlerStack;
    use Spatie\GuzzleRateLimiterMiddleware\RateLimiterMiddleware;

    define('CALLBACK_URI','https://xxx.yyy/zzzzzzzz.php');
    define('HARVEST_CLIENT_ID','xxxxxxxxxxxxxxxxxxxxxxxx');
    define('HARVEST_CLIENT_SECRET','xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
    define('HARVEST_USER_AGENT','My Harvest Integration');
    define('HARVEST_ACCOUNT_ID','xxxxxx');

    // Add a rate limiter
    $stack=HandlerStack::create();
    $stack->push(RateLimiterMiddleware::perSecond(6));
    $options=['debug' => $debug, 'exceptions' => false, 'handler' => $stack];
    $httpClient = new Client($options);

    $this->provider = \GlobalVisionMedia\OAuth2\HarvestClient\Provider\Harvest([
        'redirectUri'       => CALLBACK_URI,
        'clientId'          => HARVEST_CLIENT_ID,
        'clientSecret'      => HARVEST_CLIENT_SECRET,
        'username'          => HARVEST_ACCOUNT_ID,
        'password'          => HARVEST_USER_AGENT
      ],
      ['httpClient'         => $httpClient]);

# Sample application
    <?php
    require __DIR__ . '/vendor/autoload.php';

    // This is a prebuilt rate limiter for guzzle - unfortunately MYOB does not seem to work as documented any you may need to add additional sleep() calls.
  
    use GuzzleHttp\Client;
    use GuzzleHttp\HandlerStack;
    use Spatie\GuzzleRateLimiterMiddleware\RateLimiterMiddleware;
  
    define('CALLBACK_URI','https://xxx.yyy/zzzzzzzz.php');
    define('HARVEST_CLIENT_ID','xxxxxxxxxxxxxxxxxxxxxxxx');
    define('HARVEST_CLIENT_SECRET','xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
    define('HARVEST_USER_AGENT','My Harvest Integration');
    define('HARVEST_ACCOUNT_ID','xxxxxx');
  
    define('CACHEDIR','/tmp/');                                      // a writeable area for storing tokens
  
  
    class myHarvest {
  
      public function __construct($debug=false) {
        $this->cache=CACHEDIR.'_API_TOKEN_CACHE_'.md5(__FILE__.get_class($this));
  
        // Add the rate limiter
        $stack=HandlerStack::create();
        $stack->push(RateLimiterMiddleware::perSecond(6));
        $options=['debug' => $debug, 'exceptions' => false, 'handler' => $stack];
        $httpClient = new Client($options);
  
        $this->provider = \GlobalVisionMedia\OAuth2\HarvestClient\Provider\Harvest([
            'redirectUri'       => CALLBACK_URI,
            'clientId'          => HARVEST_CLIENT_ID,
            'clientSecret'      => HARVEST_CLIENT_SECRET,
            'username'          => HARVEST_ACCOUNT_ID,
            'password'          => HARVEST_USER_AGENT
          ],
          ['httpClient'         => $httpClient]);
  
        // First check our cache to see if we have an existing token. This sppeds the application by avoiding the need to re-authenticate.
        if (file_exists($this->cache)) {
          $this->accessToken=unserialize(file_get_contents($this->cache));
          if ($this->accessToken->hasExpired()) {
            $this->accessToken=$this->provider->getAccessToken('refresh_token', ['refresh_token'=>8]);
          }
        } elseif (!isset($_GET['code'])) {
          // If we don't have an authorization code then get one
          $authUrl = $this->provider->getAuthorizationUrl();
          $_SESSION['oauth2state'] = $this->provider->getState();
  
          header('Location: '.$authUrl);
          exit;
  
          // Check given state against previously stored one to mitigate CSRF attack
        } elseif (empty($_GET['state']) ||
                  (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
          if (isset($_SESSION['oauth2state'])) unset($_SESSION['oauth2state']);
          exit('Invalid state');
  
          // Try to get an access token using the authorisation code grant.
        } else try {
          $this->accessToken = $this->provider->getAccessToken('authorization_code', [ 'code' => $_GET['code'] ]);
  
          // Cache the token
          file_put_contents($this->cache,serialize($this->accessToken));
  
        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
          // Failed to get the access token or user details.
          exit($e->getMessage());
        }
      }
  
      public function getItemsAsArray($result) {
        $keys=array_keys($result);
        //find whichever key is not in the following list - it must be our data.
        $dataKey=array_diff($keys,['page','total_pages','total_entries','next_page','previous_page','links']);
        return $result[$dataKey[0]];
      }

      public function apiCall($method, $url, $pageSize=100) {
        if (strpos($url,"https://")===false) {  // is this a nextpage link? if so leave url unchanged
          $url="https://api.harvestapp.com/v2$url?per_page=$pageSize";
        }
        $request=$this->provider->AuthenticatedRequest($method, $url, $this->accessToken);
        return $this->provider->getParsedResponse($request);
      }
  
      // This function retrieves paginated data as a single array
      public function fetchAll($method, $url, $pageSize=100) {
        $allResults=array();
        do {
          $result=$this->apiCall($method,$url,$pageSize);
          $allResults=array_merge($allResults,$this->getItemsAsArray($result));
          $url = $result['links']['next'];
        } while (!empty($url));
        return $allResults;
      }
  
    }
  
    session_start();
    $myHarvest=new myHarvest();
    print_r($myHarvest->fetchAll('GET', '/contacts'));
