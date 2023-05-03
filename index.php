<?php

class AppPasswordsPlugin extends \RainLoop\Plugins\AbstractPlugin
{
    public function Init()
    {
        // Register the Add App Password template
        $this->RegisterTemplate('AppPasswords_Add', __DIR__.'/templates/AppPasswords_Add.html');

        // Register the Add App Password Success template
        $this->RegisterTemplate('AppPasswords_Add_Success', __DIR__.'/templates/AppPasswords_Add_Success.html');

        // Add the "Add App Password" link to the RainLoop menu
        $this->addAppPasswordLink();

        // Register the AppPasswords_Save method as a RainLoop API method
        $this->addApiEndpoint('AppPasswords_Save', 'api/AppPasswords_Save');

        // Register the AppPasswords_Delete method as a RainLoop API method
        $this->addApiEndpoint('AppPasswords_Delete', 'api/AppPasswords_Delete');
    }

    private function addAppPasswordLink()
    {
        // Get the RainLoop instance
        $oHttp = \RainLoop\Http::SingletonInstance();

        // Get the template engine
        $oTemplate = $this->Template();

        // Add the "Add App Password" link to the RainLoop menu
        $oTemplate->Assign('AppPasswords_Link', $oHttp->Url('plugin/app_passwords', false));
        $oTemplate->Assign('AppPasswords_Link_Text', _('Add App Password'));
        $oTemplate->Append('Menu', $oTemplate->Fetch('AppPasswords_Link', 'templates/AppPasswords_Link.html'));
    }

    public function AppPasswords_Save()
    {
        $aResult = array(
            'Error' => false,
            'Message' => ''
        );

        // Get the current user's email address
        $sEmail = $this->getEmailAddress();

        // Get the new app password details from the POST data
        $sDescription = isset($_POST['description']) ? trim($_POST['description']) : '';
        $iExpiresIn = isset($_POST['expires_in']) ? intval($_POST['expires_in']) : 0;

        // Generate a random password
        $sPassword = bin2hex(openssl_random_pseudo_bytes(16));

        // Hash the password using MD5
        $sPasswordHash = crypt($sPassword, '$1$' . $sEmail);

        // Add the new app password to the Exim password file
        $this->addAppPasswordToExim($sEmail, $sDescription, $sPasswordHash, $iExpiresIn);

        // Generate the success message
        $sMessage = _('Your new app password has been generated:');
        $sMessage .= '<br><br>';
        $sMessage .= '<strong>' . _('Description:') . '</strong> ' . htmlspecialchars($sDescription) . '<br>';
        $sMessage .= '<strong>' . _('App Password:') . '</strong> ' . htmlspecialchars($sPassword) . '<br>';

        // Check if the password will expire
        if ($iExpiresIn > 0) {
            $iExpiresAt = time() + $iExpiresIn;
            $sExpiresAt = date('Y-m-d H:i:s', $iExpiresAt);
            $sMessage .= '<strong>' . _('Expires At:') . '</strong> ' . htmlspecialchars($sExpiresAt) . '<br>';
        }

        // Return the success message
        $aResult['Message'] = $sMessage;
        return $aResult;
    }
public function AppPasswords_Delete()
    {
        $aResult = array(
            'Error' => false,
            'Message' => ''
        );

        // Get the current user's email address
        $sEmail = $this->getEmailAddress();

        // Get the app password ID from the POST data
        $iAppPasswordId = isset($_POST['id']) ? intval($_POST['id']) : 0;

        // Remove the app password from the Exim password file
        $this->removeAppPasswordFromExim($sEmail, $iAppPasswordId);

        // Generate the success message
        $sMessage = _('The app password has been deleted.');

        // Return the success message
        $aResult['Message'] = $sMessage;
        return $aResult;
    }

    private function getEmailAddress()
    {
        // Get the current user's email address
        $oAccount = \RainLoop\Account::NewInstance();
        return $oAccount->Email();
    }

    private function addAppPasswordToExim($sEmail, $sDescription, $sPasswordHash, $iExpiresIn)
    {
        // Get the domain name from the email address
        list($sUsername, $sDomain) = explode('@', $sEmail);

        // Set the path to the Exim password file
        $sEximPasswdFile = '/etc/exim4/domains/' . $sDomain . '/passwd';

        // Create the Exim password file if it doesn't exist
        if (!file_exists($sEximPasswdFile)) {
            file_put_contents($sEximPasswdFile, '');
            chmod($sEximPasswdFile, 0600);
        }

        // Generate a unique ID for the app password
        $iAppPasswordId = time();

        // Generate the line to add to the Exim password file
        $sLine = $sEmail . ':' . $iAppPasswordId . ':' . $sDescription . ':' . $sPasswordHash;

        // Check if the password will expire
        if ($iExpiresIn > 0) {
            $iExpiresAt = time() + $iExpiresIn;
            $sExpiresAt = date('Y-m-d H:i:s', $iExpiresAt);
            $sLine .= ':' . $sExpiresAt;
        }

        // Add the line to the Exim password file
        file_put_contents($sEximPasswdFile, $sLine . "\n", FILE_APPEND | LOCK_EX);
    } 
private function removeAppPasswordFromExim($sEmail, $iAppPasswordId)
    {
        // Load the existing Exim password file
        $sDomain = substr(strrchr($sEmail, "@"), 1);
        $sEximPasswdFile = "/etc/exim4/domains/$sDomain/passwd";
        $aLines = @file($sEximPasswdFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$aLines) {
            throw new Exception("Failed to load Exim password file for domain: $sDomain");
        }

        // Find the existing app password and remove it
        $bRemoved = false;
        for ($i = 0; $i < count($aLines); $i++) {
            if (preg_match("/^$sEmail:\(APP\)([0-9]+):(.*)$/", $aLines[$i], $aMatches)) {
                if ($aMatches[1] == $iAppPasswordId) {
                    array_splice($aLines, $i, 1);
                    $bRemoved = true;
                    break;
                }
            }
        }

        if (!$bRemoved) {
            throw new Exception("Failed to find App Password with ID $iAppPasswordId for email address: $sEmail");
        }

        // Write the updated Exim password file
        file_put_contents($sEximPasswdFile, implode("\n", $aLines) . "\n");
    }

    private function getPasswordHash($sPassword)
    {
        $sSalt = '';
        $sChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

        for ($i = 0; $i < 8; $i++) {
            $sSalt .= $sChars[mt_rand(0, strlen($sChars) - 1)];
        }

        return md5($sSalt . $sPassword) . ':' . $sSalt;
    }
}