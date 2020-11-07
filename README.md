# plugin_security

Plugin Security pour MKFramework
Ajout d'une sécurté basique contre les attaques en brute force

## Installation
Placer le plugin de la dossier plugin de votre projet mkframwork


## Usage
Inscription, modifier la fonction processInscription() comme suit :
```php
	private function processInscription(){
		if(!_root::getRequest()->isPost()){
			return null;
		}
		
		$tAccount=model_account::getInstance()->getListAccount();
		
		$sLogin=_root::getParam('name');
		$sPassword=_root::getParam('password');
                
                //vérification de la complexité du mot de passe
                if (!(new plugin_security())->checkPwdComplexityOK($sPassword))
                {
                    return array('name'=>array((new plugin_security())->getPwdComplexity()));
                }
                //fin vérification de la complexité du mot de passe
                
                if($sPassword!=_root::getParam('password2')){
			return array('name'=>array('Les deux mots de passe doivent etre identiques'));
		}elseif($sLogin==''){
			return array('name'=>array('Vous devez remplir le nom d utilisateur'));
		}elseif($sPassword==''){
			return array('name'=>array('Vous devez remplir le mot de passe'));
		}elseif(strlen($sPassword) > $this->maxPasswordLength){
			return array('name'=>array('Mot de passe trop long'));
		}elseif(isset($tAccount[$sLogin]) ){
			return array('name'=>array('Utilisateur d&eacute;j&agrave; existant'));
		}

		$oAccount=new row_account;
		$oAccount->name=$sLogin;
		$oAccount->pwd=model_account::getInstance()->hashPassword($sPassword);
		if($oAccount->save()==false){

			return $oAccount->getListError();
			
		}

		return array('success'=>array('Votre compte a bien &eacute;t&eacute; cr&eacute;&eacute;'));

	}
```


editer ensuite la fonction  processInscription()
[dans l'exemple vérification sur une tentative delogin avec protection sur nom d'utilisateur et ip appelante]

```php
	private function checkLoginPass(){
		//si le formulaire n'est pas envoye on s'arrete la
		if(!_root::getRequest()->isPost() ){
			return null;
		}
		
		$sLogin=_root::getParam('login');
		$sPassword=_root::getParam('password');
		
		if(strlen($sPassword) > $this->maxPasswordLength){
			return 'Mot de passe trop long';
		}
                
                // contre mesure brute force
		if ((new plugin_security())->checkIsLock("login",$sLogin))
                {
                    return 'Connexion temporairement désactivée (erreur 22)';
                }
                if ((new plugin_security())->checkIsLock("ip",$_SERVER['REMOTE_ADDR']))
                {
                    return 'Connexion temporairement désactivée (erreur 22)';
                }
                // Fin contre mesure brute force

		//on stoque les mots de passe hashe dans la classe model_account
		$sHashPassword=model_account::getInstance()->hashPassword($sPassword);
		$tAccount=model_account::getInstance()->getListAccount();

		//on va verifier que l'on trouve dans le tableau retourne par notre model
		//l'entree $tAccount[ login ][ mot de passe hashe ]
		if(!_root::getAuth()->checkLoginPass($tAccount,$sLogin,$sHashPassword)){
                        // Ajout modification pour plugin security 
                        (new plugin_security())->preventBF("login",$sLogin); // protection sur le login
                        (new plugin_security())->preventBF("ip",$_SERVER['REMOTE_ADDR']); // protection sur l'ip
                        // FIN Ajout modification pour plugin security 
                        return 'Erreur utilisateur/mot de passe';
        	}
		_root::redirect('default::index');
	}

```

## A noter
Le dossier data doit etre en ecriture, le plgin travail en systeme de fichier (pas de bdd)


