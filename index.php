<?php

class RainloopAppPasswordsPlugin extends RainloopPlugin
{
    public function init()
    {
        $this->addHook('app_passwords', array($this, 'addAppPasswords'));
        $this->addHook('app_password_delete', array($this, 'deleteAppPassword'));
    }

    public function addAppPasswords()
    {
        $app_password = $this->getRequest()->post('app_password');
        $username = $this->getRequest()->post('username');

        if (empty($app_password) || empty($username)) {
            return;
        }

        $this->addAppPasswordToEXIM($app_password, $username);

        $this->addFlash('success', 'App password added successfully.');
    }

    private function addAppPasswordToEXIM($app_password, $username)
    {
        $file = fopen('/etc/exim4/domains/domainname/passwd', 'a');

        if ($file) {
            fwrite($file, "$username:$app_password\n");
            fclose($file);
        }
    }

    public function deleteAppPassword()
    {
        $app_password_id = $this->getRequest()->post('app_password_id');

        if (empty($app_password_id)) {
            return;
        }

        $this->deleteAppPasswordFromEXIM($app_password_id);

        $this->addFlash('success', 'App password deleted successfully.');
    }

    private function deleteAppPasswordFromEXIM($app_password_id)
    {
        $file = fopen('/etc/exim4/domains/domainname/passwd', 'r');

        if ($file) {
            $lines = array();
            while (($line = fgets($file)) !== false) {
                $parts = explode(':', $line);
                if ($parts[0] !== $app_password_id) {
                    $lines[] = $line;
                }
            }
            fclose($file);

            $file = fopen('/etc/exim4/domains/domainname/passwd', 'w');
            if ($file) {
                foreach ($lines as $line) {
                    fwrite($file, $line);
                }
                fclose($file);
            }
        }
    }
}

?>
