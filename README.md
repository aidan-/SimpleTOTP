SimpleTOTP
==========
SimpleTOTP is a [SimpleSAMLphp](https://simplesamlphp.org/) [auth processing filter](https://simplesamlphp.org/docs/stable/simplesamlphp-authproc) that enables the use of the *Time-Based One-Time Password Algorithm* (TOTP) as a second-factor authentication mechanism on either an Identity Provider or Service Provider (...or both!).

This has been tested with *Google Authenticator* on iOS and Android.

Why?
---
While a there are a few two-factor authentication modules that already exist for SimpleSAMLphp, they are all implemented as [authentication sources](https://simplesamlphp.org/docs/stable/simplesamlphp-authsource).

As an auth processing filter, this module is flexible in a number of ways:

* agnostic to where the TOTP secret is stored
* can be enabled on select Service Providers or an entire Identity Provider

Usage
-----
Like any other auth process filter, this module needs to be configured in an authproc array in either config.php or in the metadata for a particular service provider or identity provider.

### Prerequisites

The ```secret_attr``` needs to be available in the attribute payload as it is used to generate the token for comparison.  This can be added using other auth process filters to look up an external databases of sorts (SQL, LDAP, etc).

After the module has been called, the attribute will be moved out of the user attribute array.  As a safety precaution an extra step should be taken ensure this attribute is removed.  This can be done using the ```core:AttributeAlter``` filter or similar.

### Example

Placed in either config.php's authproc or in the appropriate metadata entity:
```php
10 => array(
	'class' => 'simpletotp:2fa',
	'secret_attr' => 'totp_secret', //default
	'enforce_2fa' => false, //default
	'not_configured_url' => NULL,  //default
),
```

Placed in config.php authproc as one of the last functions to be processed:

```php
99 => array(
	'class' => 'core:AttributeAlter',
	'subject' => 'ga_secret',
	'pattern' => '/.*/',
	'%remove',
),
```

Example of how it can work with example-userpass module. Below config goes in authsource.php
This module is enabled by default but if it is not make sure you create a file called enable
inside modules/exampleauth directory.

```php
	'example-userpass' => array(
		'exampleauth:UserPass',
		'student:studentpass' => array(
			'uid' => array('test'),
			'ga_secret' => array('4HX4WBKVIJWDUV5I'),
			'eduPersonAffiliation' => array('member', 'student'),
		),
	),
```

After logging in with username: student password: studentpass, you will be challenged for TOTP.
4HX4WBKVIJWDUV5I is a secret key that can be generate by visiting /simplesaml/module.php/simpletotp/generate_token.php

A random one will be generated everytime. You can also use the QR code to register your IdP with apps such as FreeOTP
or Google Authenticator etc.


**NOTE**: for TOTP to work you **MUST** ensure that the clock on your server is in sync.  If it is not, a matching token will never be generated and authentication will fail.

Installation
------------
### Via Git
A simple ```git clone``` in the SimpleSAMLphp module directory is all that is required.
### Via Composer
```composer.phar require aidan/simplesamlphp-module-simpletotp```

TODO
----
* improve usage documentation with examples using external database(s) as data sources
* add basic brute force prevention
