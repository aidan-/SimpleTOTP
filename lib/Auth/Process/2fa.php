<?php
/**
 * SimpleTOTP Authentication Processing filter
 *
 * SimpleTOTP is a SimpleSAMLphp auth processing filter that enables the use
 *  of the Time-Based One-Time Password Algorithm (TOTP) as a second-factor
 *  authentication mechanism on either an Identity Provider or Service Provider
 *  (...or both!).
 *
 * This has been tested with Google Authenticator on iOS and Android.
 *
 * <code>
 *  10 => array(
 *    'class' => 'simpletotp:2fa',
 *    'secret_attr' => 'totp_secret', //default
 *    'enforce_2fa' => false, //default
 *    'not_configured_url' => NULL,  //default
 *  ),
 * </code>
 *
 * @package simpleSAMLphp
 */

class sspmod_simpletotp_Auth_Process_2fa extends SimpleSAML_Auth_ProcessingFilter {
    /**
     * Attribute that stores the TOTP secret
     */
    private $secret_attr = 'totp_secret';

    /**
     * Value of the TOTP secret
     */
    private $secret_val = NULL;

    /**
     * Whether or not the user should be forced to use 2fa.
     *  If false, a user that does not have a TOTP secret will be able to continue
     *   authentication
     */
    private $enforce_2fa = false;

    /**
     * External URL to redirect user to if $enforce_2fa is true and they do not
     *  have a TOTP attribute set.  If this attribute is NULL, the user will
     *  be redirect to the internal error page.
     */
    private $not_configured_url = NULL;

    /**
     * Initialize the filter.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use
     */
    public function __construct($config, $reserved) {
        parent::__construct($config, $reserved);

        assert('is_array($config)');

        if (array_key_exists('enforce_2fa', $config)) {
            $this->enforce_2fa = $config['enforce_2fa'];
            if (!is_bool($this->enforce_2fa)) {
                throw new Exception('Invalid attribute name given to simpletotp::2fa filter:
 enforce_2fa must be a boolean.');
            }
        }

        if (array_key_exists('secret_attr', $config)) {
            $this->secret_attr = $config['secret_attr'];
            if (!is_string($this->secret_attr)) {
                throw new Exception('Invalid attribute name given to simpletotp::2fa filter:
 secret_attr must be a string');
            }
        }

        if (array_key_exists('not_configured_url', $config)) {
            $this->not_configured_url = $config['not_configured_url'];
            if (!is_string($config['not_configured_url'])) {
                throw new Exception('Invalid attribute value given to simpletotp::2fa filter:
 not_configured_url must be a string');
            }

            //validate URL to ensure it's we will be able to redirect to
            $this->not_configured_url =
            SimpleSAML_Utilities::checkURLAllowed($config['not_configured_url']);
        }
    }

    /**
     * Apply SimpleTOTP 2fa filter
     *
     * @param array &$state  The current state
     */
    public function process(&$state) {
        assert('is_array($state)');
        assert('array_key_exists("Attributes", $state)');

        $attributes =& $state['Attributes'];

        // check for secret_attr coming from user store and make sure it is not empty
        if (array_key_exists($this->secret_attr, $attributes) && !empty($attributes[$this->secret_attr])) {
            $this->secret_val = $attributes[$this->secret_attr][0];
        }

        if ($this->secret_val === NULL && $this->enforce_2fa === true) {
            #2f is enforced and user does not have it configured..
            SimpleSAML_Logger::debug('User with ID xxx does not have 2f configured when it is
            mandatory for xxxSP');

            //send user to custom error page if configured
            if ($this->not_configured_url !== NULL) {
                SimpleSAML_Utilities::redirectUntrustedURL($this->not_configured_url);
            } else {
                SimpleSAML_Utilities::redirectTrustedURL(SimpleSAML_Module::getModuleURL('simpletotp/not_configured.php'));
            }

        } elseif ($this->secret_val === NULL && $this->enforce_2fa === false) {
            SimpleSAML_Logger::debug('User with ID xxx does not have 2f configured but SP does not
            require it. Continue.');
            return;
        }

        //as the attribute is configurable, we need to store it in a consistent location
        $state['2fa_secret'] = $this->secret_val;

        //this means we have secret_val configured for this session, time to 2fa
        $id  = SimpleSAML_Auth_State::saveState($state, 'simpletotp:request');
        $url = SimpleSAML_Module::getModuleURL('simpletotp/authenticate.php');
        SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));

        return;
    }
}
