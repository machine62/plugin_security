<?php

class plugin_security extends abstract_auth {

    private $bPwdUpper = true;
    private $bPwdLower = true;
    private $bPwdNumber = false;
    private $bPwdSpecial = false;
    private $iPwdLengh = 8;
    
    private $ipreventBFCount = 5; // nombre de tentative par jour 
    

    // vérification de la complexité du mot de passe
    public function checkPwdComplexityOK($pwd) {
        if (strlen($pwd) <= $this->iPwdLengh) {//longueur
            return false;
        }
        if (!preg_match('@[A-Z]@', $pwd) && $this->bPwdUpper) {//majuscule
            return false;
        }
        if (!preg_match('@[a-z]@', $pwd) && $this->bPwdLower) {//minuscule
            return false;
        }
        if (!preg_match('@[0-9]@', $pwd) && $this->bPwdNumber) {//nombre
            return false;
        }
        if (!preg_match('@[^\w]@', $pwd) && $this->bPwdSpecial) {//special
            return false;
        }
        return true;
    }

    public function getPwdComplexity() {
        $tab = array();
        $tab[] = "8 caracteres minimum";
        if ($this->bPwdUpper) {//majuscule
            $tab[] = "1 Majuscule";
        }
        if ($this->bPwdLower) {//minuscule
            $tab[] = "1 Minuscule";
        }
        if ($this->bPwdNumber) {//nombre
            $tab[] = "1 Chiffre";
        }
        if ($this->bPwdSpecial) {//special
            $tab[] = "1 caractere complexe (&,!,;,$,..)";
        }

        return "Complexité du mot de passe non atteinte [" . implode(", ", $tab) . "]";
    }

    public function preventBF($sType, $sValue) {
        $this->prepareFolder();

        $error = 0;
        $oFileLogBF = new _file('../data/bf/tmp/' . $sType . '_' . $sValue . '_bf.error');
        if ($oFileLogBF->exist()) {
            $oFileLogBF->load();
            $error = (int)$oFileLogBF->getContent();
        }
        $error++;
        $oFileLogBF->setContent($error);
        
        $this->writefile("tentative;".$sType.";".$sValue.";".$error."");
        $oFileLogBF->save();
        $oFileLogBF->clean();
    }

    // limitation dy nombre de tentative dans un temps donnée
    public function checkIsLock($sType, $sValue) {
        $this->prepareFolder();
        $oFileLogBF = new _file('../data/bf/tmp/' . $sType . '_' . $sValue . '_bf.error');
         if ($oFileLogBF->exist()) {
            $oFileLogBF->load();
            $error = (int)$oFileLogBF->getContent();
            if ($error >=  $this->ipreventBFCount )
            {
                $this->writefile("prison;".$sType.";".$sValue.";".$error."");
                return true;
            }
        }
        return false;
        }

    private function writefile($sMessage) {

        $sMessage = preg_replace('/\s+/', ' ', $sMessage);
        $pathfile = '../data/bf/log/' . date('Y-m') . '/' . date('Y-m-d') . '_bf.csv' ;

        $oFileLogBF = new _file($pathfile);
        if ($oFileLogBF->exist()) {
            $oFileLogBF->load();
        }

        $oFileLogBF->addContent(date('Y-m-d') . ';' . date('H:i:s') . ';' . $sMessage . "\n");
        $oFileLogBF->save();
        $oFileLogBF->clean();
    }

    private function prepareFolder() {
        if (!is_dir('../data/bf')) {
            $oDir = new _dir('../data/bf');
            $oDir->save();
        }
        if (!is_dir('../data/bf/log/')) {
            $oDir = new _dir('../data/bf/log/');
            $oDir->save();
        }
       if (!is_dir('../data/bf/log/'.date('Y-m').'/')) {
            $oDir = new _dir('../data/bf/log/'.date('Y-m').'/');
            $oDir->save();
            // clean tmp
             if (is_dir('../data/bf/tmp'))
             {
                 $oDir = new _dir('../data/bf/tmp');
                 $oFiles = $oDir->getListFile();
                 foreach ($oFiles as $file)
                 {
                     $file->delete();
                 }
             }
            }
        if (!is_dir('../data/bf/tmp')) {
            $oDir = new _dir('../data/bf/tmp');
            $oDir->save();
        }
    }

}
