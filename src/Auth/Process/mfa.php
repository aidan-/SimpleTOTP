<?php
/**
 * SimpleTOTP Authentication Processing filter
 *
 * SimpleTOTP is a SimpleSAMLphp auth processing filter that enables the use
 *  of the Time-Based One-Time Password Algorithm (TOTP) as a second-factor (aka multi-factor)
 *  authentication mechanism on either an Identity Provider or Service Provider
 *  (...or both!).
 *
 * This has been tested with Google Authenticator on iOS and Android.
 *
 * <code>
 *  10 => array(
 *    'class' => 'simpletotp:mfa',
 *    'secret_attr' => 'totp_secret', //default
 *    'enforce_mfa' => false, //default
 *    'not_configured_url' => NULL,  //default
 *  ),
 * </code>
 *
 * @package simpleSAMLphp
 */

declare(strict_types=1);

namespace SimpleSAML\Module\simpletotp\Auth\Process;
use SimpleSAML\Auth;
use SimpleSAML\Module;
use SimpleSAML\Utils;
use SimpleSAML\Logger;
use SimpleSAML\Error\Exception;
use SimpleSAML\Session;

class Mfa extends Auth\ProcessingFilter {
    /**
     * Attribute that stores the TOTP secret
     */
    private $secret_attr = 'totp_secret';

    /**
     * Value of the TOTP secret
     */
    private $secret_val = NULL;

    /**
     * Whether or not the user should be forced to use MFA.
     *  If false, a user that does not have a TOTP secret will be able to continue
     *   authentication
     */
    private $enforce_mfa = false;

    /**
     * External URL to redirect user to if $enforce_mfa is true and they do not
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

        if (array_key_exists('enforce_mfa', $config)) {
            $this->enforce_mfa = $config['enforce_mfa'];
            if (!is_bool($this->enforce_mfa)) {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: enforce_mfa must be a boolean.');
            }
        }

        if (array_key_exists('secret_attr', $config)) {
            $this->secret_attr = $config['secret_attr'];
            if (!is_string($this->secret_attr)) {
                throw new Exception('Invalid attribute name given to simpletotp::mfa filter: secret_attr must be a string');
            }
        }

        if (array_key_exists('not_configured_url', $config)) {
            $this->not_configured_url = $config['not_configured_url'];
            if ($config['not_configured_url'] !== NULL && !is_string($config['not_configured_url'])) {
                throw new Exception('Invalid attribute value given to simpletotp::mfa filter: not_configured_url must be a string');
            }

            //validate URL to ensure it's we will be able to redirect to
			$httpUtils = new Utils\HTTP();
			if (is_string($config['not_configured_url'])) {
				$this->not_configured_url =
					$httpUtils->checkURLAllowed($config['not_configured_url']);
			} else {
				$this->not_configured_url = NULL;
			}
        }
    }

    /**
     * Apply SimpleTOTP MFA filter
     *
     * @param array &$state  The current state
     */
    public function process(&$state): void {
        assert('is_array($state)');
        assert('array_key_exists("Attributes", $state)');

        $attributes =& $state['Attributes'];

        // check for secret_attr coming from user store and make sure it is not empty
        if (array_key_exists($this->secret_attr, $attributes) && !empty($attributes[$this->secret_attr])) {
            $this->secret_val = $attributes[$this->secret_attr][0];
        }

        if ($this->secret_val === NULL && $this->enforce_mfa === true) {
            # 2f is enforced and user does not have it configured..
// TODO - see if we can get the user ID from the Session information
            Logger::debug('User with ID XXX does not have 2f configured when it is mandatory for an idP or a SP');

            //send user to custom error page if configured
            if ($this->not_configured_url !== NULL) {
                $httpUtils = new Utils\HTTP();
                $httpUtils->redirectUntrustedURL($this->not_configured_url);
            } else {
                $httpUtils = new Utils\HTTP();
				$httpUtils->redirectTrustedURL(Module::getModuleURL('simpletotp/not_configured.php'));
            }

        } elseif ($this->secret_val === NULL && $this->enforce_mfa === false) {
            Logger::debug('User with ID XXX does not have 2f configured but SP does not require it. Continue.');
            return;
        }

        //as the attribute is configurable, we need to store it in a consistent location
        $state['mfa_secret'] = $this->secret_val;

        //this means we have secret_val configured for this session, time to MFA
		$now = time();

		// check to see if MFA has been verified in the last hour
		$session = Session::getSessionFromRequest();
		$alldata = $session->getDataOfType('\SimpleSAML\Module\simpletotp');
		Logger::debug('MFA: alldata ' . implode(',', array_keys($alldata)));
		Logger::debug('MFA: alldata lastverified ' . $alldata['lastverified']);
		$lastverified = $session->getData('\SimpleSAML\Module\simpletotp', 'lastverified');
		Logger::debug('MFA: last verified ' . $lastverified);
		Logger::debug('MFA: time ' . $now);

		if ( ($lastverified === NULL) || ($now - $lastverified) > (60 * 60) ){
			// update if re-verification required
			$session->setData(
				'\SimpleSAML\Module\simpletotp',
				'lastverified',
				$now,
				Session::DATA_TIMEOUT_SESSION_END
			);
			if ( $lastverified === NULL ) {
				$reason = 'new session';
			} else {
				$reason = ($now - $lastverified) . 's ago';
			}
			Logger::info('MFA: verification required.  New session or last verified more than an hour ago - ' . $reason);
		} else {
			// nothing more to do here
			Logger::info('MFA: already verified in the last hour - ' . ($now - $lastverified) . 's ago');
			return;
		}

        $id  = Auth\State::saveState($state, 'simpletotp:request');
        $url = Module::getModuleURL('simpletotp/authenticate.php');
		$httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($url, array('StateId' => $id));

        return;
    }
}
