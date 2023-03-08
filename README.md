# JWT

A simple library to work with JSON Web Token and JSON Web Signature (requires PHP 5.6+).
The implementation is based on the [RFC 7519](https://tools.ietf.org/html/rfc7519).

The `code` is from [lcobucci/jwt](https://github.com/lcobucci/jwt)


## Installation

you can install it using [Composer](http://getcomposer.org).

```shell
composer require lake/larke-jwt
```

### Dependencies

- PHP 8.1.0+
- OpenSSL Extension
- sodium Extension

## Basic usage

### Creating

Just use the builder to create a new JWT/JWS tokens:

```php
use DateTimeImmutable;
use Larke\JWT\Builder;
use Larke\JWT\Signer\None;
use Larke\JWT\Signer\Key\InMemory;

$now    = new DateTimeImmutable();
$signer = new None();
$key    = InMemory::plainText('testing')

$token = (new Builder())
    ->issuedBy('http://example.com') // Configures the issuer (iss claim)
    ->permittedFor('http://example.org') // Configures the audience (aud claim)
    ->identifiedBy('4f1g23a12aa', true) // Configures the id (jti claim), replicating as a header item
    ->issuedAt($now) // Configures the time that the token was issue (iat claim)
    ->canOnlyBeUsedAfter($now->modify('+1 minute')) // Configures the time that the token can be used (nbf claim)
    ->expiresAt($now->modify('+1 hour')) // Configures the expiration time of the token (exp claim)
    ->withClaim('uid', 1) // Configures a new claim, called "uid"
    ->getToken($signer, $key); // Retrieves the generated token

$token->headers()->all(); // Retrieves the token headers
$token->claims()->all(); // Retrieves the token claims

echo $token->headers()->get('jti'); // will print "4f1g23a12aa"
echo $token->claims()->get('iss'); // will print "http://example.com"
echo $token->claims()->get('uid'); // will print "1"
echo $token->toString(); // The string representation of the object is a JWT string (pretty easy, right?)
```

### Parsing from strings

Use the parser to create a new token from a JWT string (using the previous token as example):

```php
use Larke\JWT\Parser;

$token = (new Parser())->parse((string) $token); // Parses from a string
$token->headers()->all(); // Retrieves the token headers
$token->claims()->all(); // Retrieves the token claims

echo $token->headers()->get('jti'); // will print "4f1g23a12aa"
echo $token->claims()->get('iss'); // will print "http://example.com"
echo $token->claims()->get('uid'); // will print "1"
```

### Validating

We can easily validate if the token is valid (using the previous token and time as example):

```php
use DateTimeImmutable;
use Larke\JWT\Validator;
use Larke\JWT\ValidationData;

$now = new DateTimeImmutable();

$data = new ValidationData(); // It will use the current time to validate (iat, nbf and exp)
$data->issuedBy('http://example.com');
$data->permittedFor('http://example.org');
$data->identifiedBy('4f1g23a12aa');

$validation = new Validator();

var_dump($validation->validate($token, $data)); // false, because token cannot be used before now() + 60

$data->currentTime($now->modify('+61 seconds')); // changing the validation time to future

var_dump($validation->validate($token, $data)); // true, because current time is between "nbf" and "exp" claims

$data->currentTime($now->modify('+4000 seconds')); // changing the validation time to future

var_dump($validation->validate($token, $data)); // false, because token is expired since current time is greater than exp

// We can also use the $leeway parameter to deal with clock skew (see notes below)
// If token's claimed now is invalid but the difference between that and the validation time is less than $leeway, 
// then token is still considered valid
$dataWithLeeway = new ValidationData($now, 20); 
$dataWithLeeway->issuedBy('http://example.com');
$dataWithLeeway->permittedFor('http://example.org');
$dataWithLeeway->identifiedBy('4f1g23a12aa');

var_dump($validation->validate($token, $dataWithLeeway)); // false, because token can't be used before now() + 60, not within leeway

$dataWithLeeway->currentTime($now->modify('+51 seconds')); // changing the validation time to future

var_dump($validation->validate($token, $dataWithLeeway)); // true, because current time plus leeway is between "nbf" and "exp" claims

$dataWithLeeway->currentTime($now->modify('+3610 seconds')); // changing the validation time to future but within leeway

var_dump($validation->validate($token, $dataWithLeeway)); // true, because current time - 20 seconds leeway is less than exp

$dataWithLeeway->currentTime($now->modify('+4000 seconds')); // changing the validation time to future outside of leeway

var_dump($validation->validate($token, $dataWithLeeway)); // false, because token is expired since current time is greater than exp
```

#### Important

- You have to configure ```ValidationData``` informing all claims you want to validate the token.
- If ```ValidationData``` contains claims that are not being used in token or token has claims that are not
configured in ```ValidationData``` they will be ignored by ```Token::validate()```.
- ```exp```, ```nbf``` and ```iat``` claims are configured by default in ```ValidationData::__construct()```
with the current time (```DateTimeImmutable```).
- The optional ```$leeway``` parameter of ```ValidationData``` will cause us to use that number of seconds of leeway 
when validating the time-based claims, pretending we are further in the future for the "Issued At" (```iat```) and "Not 
Before" (```nbf```) claims and pretending we are further in the past for the "Expiration Time" (```exp```) claim. This
allows for situations where the clock of the issuing server has a different time than the clock of the verifying server, 
as mentioned in [section 4.1 of RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1).

## Token signature

We can use signatures to be able to verify if the token was not modified after its generation. This library implements `Hmac`, `RSA`, `ECDSA`, `EdDSA` and `Blake2b` signatures (using 256, 384 and 512). The `none` is not signatures.

### Important

Do not allow the string sent to the Parser to dictate which signature algorithm
to use, or else your application will be vulnerable to a [critical JWT security vulnerability](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries).

The examples below are safe because the choice in `Signer` is hard-coded and
cannot be influenced by malicious users.

### Hmac and Blake2b

Hmac signatures are really simple to be used:

```php
use DateTimeImmutable;
use Larke\JWT\Builder;
use Larke\JWT\Validator;
use Larke\JWT\Signer\Hmac\Sha256;
use Larke\JWT\Signer\Key\InMemory;

$now    = new DateTimeImmutable();
$signer = new Sha256();
$key    = InMemory::plainText('testing');

$token = (new Builder())
    ->issuedBy('http://example.com') // Configures the issuer (iss claim)
    ->permittedFor('http://example.org') // Configures the audience (aud claim)
    ->identifiedBy('4f1g23a12aa', true) // Configures the id (jti claim), replicating as a header item
    ->issuedAt($now) // Configures the time that the token was issue (iat claim)
    ->canOnlyBeUsedAfter($now->modify('+1 minute')) // Configures the time that the token can be used (nbf claim)
    ->expiresAt($now->modify('+1 hour')) // Configures the expiration time of the token (exp claim)
    ->withClaim('uid', 1) // Configures a new claim, called "uid"
    ->getToken($signer, $key); // Retrieves the generated token

$key1 = InMemory::plainText('testing 1');
$key2 = InMemory::plainText('testing');

$validation = new Validator();

var_dump($validation->verify($token, $signer, $key1)); // false, because the key is different
var_dump($validation->verify($token, $signer, $key2)); // true, because the key is the same
```

### RSA, ECDSA and EdDSA

RSA, ECDSA and EdDSA signatures are based on public and private keys so you have to generate using the private key and verify using the public key:

```php
use DateTimeImmutable;
use Larke\JWT\Builder;
use Larke\JWT\Validator;
use Larke\JWT\Signer\Key\LocalFileReference;
use Larke\JWT\Signer\Rsa\Sha256; // you can use Larke\JWT\Signer\Ecdsa\Sha256 if you're using ECDSA keys

$now        = new DateTimeImmutable();
$signer     = new Sha256();
$privateKey = LocalFileReference::file('file://{path to your private key}');

$token = (new Builder())
    ->issuedBy('http://example.com') // Configures the issuer (iss claim)
    ->permittedFor('http://example.org') // Configures the audience (aud claim)
    ->identifiedBy('4f1g23a12aa', true) // Configures the id (jti claim), replicating as a header item
    ->issuedAt($now) // Configures the time that the token was issue (iat claim)
    ->canOnlyBeUsedAfter($now->modify('+1 minute')) // Configures the time that the token can be used (nbf claim)
    ->expiresAt($now->modify('+1 hour')) // Configures the expiration time of the token (exp claim)
    ->withClaim('uid', 1) // Configures a new claim, called "uid"
    ->getToken($signer, $privateKey); // Retrieves the generated token

$publicKey = LocalFileReference::file('file://{path to your public key}');

$validation = new Validator();

var_dump($validation->verify($token, $signer, $publicKey)); // true when the public key was generated by the private one =)
```

**It's important to say that if you're using RSA keys you shouldn't invoke ECDSA signers (and vice-versa), otherwise ```sign()``` and ```verify()``` will raise an exception!**
