s class is used for all user authentication. Both oauth and normal login
 * It's also used by Cl_Controller_Plugin preDispatch hook to check (be it persistent or not) user authentication
 * 
 * Note that there are 2 kinds of tokens: 
 * 	- cookie token for persistent login
 *  - email token for verifying email
 */
class Cl_Auth_Adapter_PersistentDb implements Zend_Auth_Adapter_Interface
{ 
	private $inputData; //array consiting keys like 'id', 'oauth_id', 'token', 'password'
	
	//used for Zend_Auth_Result;
	private $_user = null;
	private $_code = Zend_Auth_Result::SUCCESS;
    private $_err_code = Zend_Auth_Result::FAILURE_IDENTITY_NOT_FOUND;
	private $_messages = array();
	
	private $_page; //'login' or 'internal_login'. If internal_login, user is automatically logged in by system
	//this happens in cases after activating or something similar

	
	private $_token = ''; //cookie token
	private $_type = '';  //1 is rest | 2 is web 
	
	public function __construct($inputData = null, $page = 'login')
	{
		$this->inputData = $inputData;
		$this->_page = $page;
		$this->_type = is_rest() ? 1 : 2 ;
	}
	
	public function authenticate()
	{
		$inputData = $this->inputData;
		$dao = Dao_User::getInstance();
		if ($this->_page == 'internal_login') //user is automatically logged in
		{
			$r = array('success' =>true, 'result' => $this->inputData);
		}
		else 
		{
    		//STEP 1: Construct condition data to authenticate
            //check persistent login with cookie values : cl_uid, cl_uhash, cl_token
            if (isset($inputData['check_persistent_connection'])) //cookie or REST token
            {
            	if (
    				is_null($uid = get_cookie('uid')) || 
    				is_null($uhash = get_cookie('uhash')) ||
    				is_null($token = get_cookie('token'))
    			)
    			{
    				$this->_messages = array ("Error: No token sent !");
    				return $this->_formatResult();
    			}
    			else //some cookie
    			{
    				if ($uhash != auth_generate_uhash($uid)) 
    				{
    					$this->_messages = array("Wrong pair of uid and uhash");
    				}
    				else 
    				{
    					$this->oldToken = (string)$token;
    					$whereCond = array('id' => $uid, 
    								   'token' => array('$elemMatch' => 
    								   		array(
    								   			'token' => (string)$token,
    								   			'type' => $this->_type
    								   		)) 
    							);
    				}
    			}
            }
           	else
           	{
           		if(!isset($inputData['oauth_type'])) 
            	{
            		if (in_array($this->_page, array('register', 'activate')))
            		{
            		   	$whereCond = array('id' => $inputData['id'], 'pass' => $inputData['pass'],
            		   				  'lname' => $inputData['lname']
            		   			);
            		}
            		else //login
            		{
    		           	$pass = Cl_Dao_Util::computePasswordHash($inputData['pass']);
    		            //$whereCond = array('lname' => $inputData['lname'], 'pass' => $pass);
    		            // login with login name or email ?
    		            $whereCond = array(
    		            		'$or' => array(
    		            				array('lname' => $inputData['lname']), 
    		            				array('mail' => $inputData['lname'])
    		            		),
    		            		'pass' => $pass
    		            );
            		}
            	}
    	        else{
    	        	if (isset($inputData['id']) && $inputData['id'] != '' && !is_null($inputData['id']))
    	        	{
	    	            $whereCond = array("oauth.{$inputData['oauth_type']}.id" => $inputData['id']);
	    	            //TODO: do we need access_token?
	    	            $oauthType = $inputData['oauth_type'];
	    	            //unset($inputData['oauth_type']);
	    	            $oauth_data = $inputData;
    	        	}
    	        	else //somehow authenticate failed with twitter or fb or google...
    	        		return $this->_formatResult();
    	        }
            }
            if (!isset($whereCond))
            {
                return $this->_formatResult();
            }
            $r = $dao->authenticate($whereCond);
        }
        if ($r['success']) {
            //STEP 2: authentication success
            $this->_u = $this->_user = $r['result'];
            $where = array('id' => $this->_user['id']);
            if($this->_token == "" || ($this->_token != $this->oldToken)){
            	//remover token rest
            	$t = $dao->update($where, array('$pull' => array('token' => array('type' => 1))));
            	if(!$t['success'])
            		$this->_messages = array ($t['err']);
            	$this->_token = (string)new MongoId();
            	$token = array(
            			'token' => $this->_token,
            			'ts' => time(),
            			'type' => $this->_type,
            			'expire' => ''
            	);
            	// if tokens number > TOKEN_PERSISTENT_LIMIT then remove first token of web.
            	if(isset($this->_user['token']) && count($this->_user['token']) > TOKEN_PERSISTENT_LIMIT) {
            		foreach($this->_user['token'] as $key => $row){
            			if($row['type'] == 2){
            				unset($this->_user['token'][$key]);
            				break;
            			}
            		}
            		$t = $dao->update($where, array('$set' => array('token' => $this->_user['token'])));
            		if(!$t['success'])
            			$this->_messages = array ($t['err']);
            	}
            	$dataToUpdate = array(
            			'$push' => array('token' => $token),
            			'$set' => array('last_login' => time()),
            	);
            	
            }
            else{ 
            	//user session in web
            	$isExistsTokenRest = false;
            	foreach($this->_user['token'] as $key => $row){
            		if($row['type'] == 2){
            			unset($this->_user['token'][$key]);
            			$isExistsTokenRest = true;
            			break;
            		}
            	}
            	if(!is_rest() && $isExistsTokenRest){
            		$t = $dao->update($where, array('$set' => array('token' => $this->_user['token'])));
            		if(!$t['success'])
            			$this->_messages = array ($t['err']);
            	}
            	
            }
        }
        else //authenticate failed
        {
            //STEP 3: Authentication failed
        	if(isset($inputData['oauth_type'])) //user has successfully authenticated with with oauth
        	//but still failed to authenticate with database
        	//this can only happen in 2 cases
        	//1. Email collision
        	//2. First time login 
        	{
        		// check email address
        		$userExists  = false;
        		//if($inputData['mail'] == $u['oauth']['mail'] then update oauth data for this user
        		$oauthTypeList = array('google', 'yahoo', 'facebook', 'twitter');
        		foreach($oauthTypeList as $type) {
        			$mWhere[] = array('oauth.' . $type . '.mail' => $inputData['mail']);
        		}
        		$mWhere[] = array('mail' => $inputData['mail']);
        		
        		$uWhere = array('$or' => $mWhere);
        		$t = Cl_Dao_Util::getUserDao()->findOne($uWhere);
        		if($t['success'] && $t['count'] > 0 && !is_null($inputData['mail'])) {
        		    //2 cases can happen
        		    //1. Some other user has used this email and not yet activated
        		    // In this case, make user active & disable login by password
        		    // This way the other user would not be able to login by password
        		    
        		    $this->_user = $user = $t['result'];
        		    if ($user['status'] == 'unactivated' )
        		    {
            		    $dataToUpdate = array('$set' => array(
            		        'status' => 'activated'
            		        ),
            		        '$unset' => array('pass' => 1, 'activation_code' => 1)
            		    
            		    );
        		    }
        		    else 
        		    {
            		    //2. This user has used & validated this emal
            		    //In this case, update oauth
            		    $dataToUpdate = array(
            		        '$set' => array("oauth." . $inputData['oauth_type'] => $inputData)
            		    );
        		    }
        		    $this->_token = (string)new MongoId();
        		    $token = array(
        		    		'token' => $this->_token,
        		    		'ts' => time(),
        		    		'type' => $this->_type,
        		    		'expire' => ''
        		    );
        		    
        		    $where = array('id' => $this->_user['id']);
        		    $dataToUpdate['$push'] = array("token" => $token);
        		    
        		    //$dao->update(array('mail' => $inputData['mail']), $updateData);
        		}
        		else {
        			//guest is linking to oauth.
        			//This is a first-time logged in via this oauth id. Now insert new user
        			$newUser = array();
        			if(isset($oauth_data['mail'])) {
        				$newUser["mail"] = $oauth_data['mail'];
        				//unset($oauth_data['mail']);
        			}
        			/*else
        			 $newUser["mail"] = '';*/
        			 
        			$newUser["name"] = $oauth_data['name'];
        			$newUser['avatar'] = $oauth_data['avatar'];
        			$newUser["oauth"] = array($oauthType => $oauth_data);
        			
        			$this->_token = (string)new MongoId();
        			
        			$token = array(
        					'token' => $this->_token,
        					'ts' => time(),
        					'type' => $this->_type,
        					'expire' => ''
        			);
        			
        			$newUser['token'] = array($token);
        			$newUser['status'] = 'activated'; //oauth user should be activated right away
        			$r = $dao->insertUser($newUser);
        			if($r['success'] && isset($r['result']['id'])) {
        				$this->_user = $r['result']; //for cookie
        				Zend_Registry::set('new_registration', true);
        			}
        			else {
        				$this->_messages = array ("Error inserting new oauth user: " . $r['err']);
        			}
        		}
        	}
	        else {
	            //TODO: if the failure is due to unmatched cookie token (cl_token)
	            //insert notif or email them????
	        	$this->_messages = array ("Error: user not found !");
	        }
        }
        //STEP 4: If user needs to update some token, unverified mail...
        //this happens when (authentication suceeds || (fails & logged in user is linking to another oauth))
        if (isset($where) && isset($dataToUpdate)) //needs to update user table
        {
//         	v($where); v($dataToUpdate); die('uuuu');
            $r = $dao->update($where, $dataToUpdate);
            if(!$r['success']) {
            	$this->_messages = array("update user failed");
            }
            else {
            	if(isset($data['mail']))
            		Cl_Notif::getInstance()->markNotifAsRead($u,'', "require_email");
            }
        }
        return $this->_formatResult();
	}
	
	public function clearIdentity()
	{
		$u = Zend_Registry::get('user');
		if ($u['id'] != 0)
		{
    		$token = get_cookie('token');
    		$dataToUpdate = array('$pull' => array('token' => array('token' => (string)$token)));
    		$r = Cl_Dao_Util::getUserDao()->update(array('id' => $u['id']), $dataToUpdate);
    		if(!$r['success'])
    			$this->_messages = array ($r['err']);
		}
		
		//only clear the identity
		set_cookie('token','', -3600);
		set_cookie('roles','', -3600);
		set_cookie('permissions','', -3600);
		set_cookie('uiid','', -3600);
		set_cookie('money','', -3600);
		set_cookie('vmoney','', -3600);
		
		
		//affiliate campaign
		set_cookie('c','', -3600);
		set_cookie('f','', -3600);
		
		//set_cookie('co','', -3600);
		
		$auth = Zend_Auth::getInstance();
        if ($auth->hasIdentity()) {
            $auth->clearIdentity();
        }

        $auth->getStorage()->write($this->_user);
		return $this->_formatResult();
	}

	private function _formatResult()
	{
        if(is_null($this->_user))
        {
            //return new Zend_Auth_Result($this->_err_code, $this->_user, $this->_messages);
            $this->_user = guest_user();
        }
        //$this->_user['avatar'] = $this->_user['avatar'];
        if ($this->_user['id'] != 0)
        //if (!is_guest())
        {
            $this->_user['uhash'] = auth_generate_uhash($this->_user['id']);
        }
        else 
            $this->_user['uhash'] = '';
        
        Zend_Registry::set('user', $this->_user);

		$u['id'] = $this->_user['id'];
		if (isset($this->_user['iid']) && $this->_user['iid'] !== '')
		{
			$u['iid'] = $this->_user['iid'];
		}
		$u['name'] = $this->_user['name'];
		if (isset($this->_user['avatar']))
			$u['avatar'] = $this->_user['avatar'];
		
		$u['uhash'] = $this->_user['uhash'];
		if (isset($this->_user['counter']) && isset($this->_user['counter']['vmoney']))
			$u['vmoney'] = $this->_user['counter']['vmoney'];
		if (isset($this->_user['counter']) && isset($this->_user['counter']['money']))
			$u['money'] = $this->_user['counter']['money'];
				
        if(isset($this->_user['mail']))
            $u['mail'] = $this->_user['mail'];
		$this->setAuthCookie($u);
 		return new Zend_Auth_Result($this->_code, $u, $this->_messages);
	}
	
	public function setAuthCookie($u, $extendExpiryOnly = false)
	{
		//always set uid, uhash
		if (!$extendExpiryOnly)
		{
			set_cookie('uid', $u['id']);
			set_cookie('uname', $u['name']);
			set_cookie('uhash', $u['uhash']);
			set_cookie('token', $this->_token);
			/*
			if (isset($u['money']) && $u['money'] !== '')
				set_cookie('money', $u['money']);

			if (isset($u['vmoney']) && $u['vmoney'] !== '')
				set_cookie('vmoney', $u['vmoney']);
		    */
					
			if (isset($u['iid']) && $u['iid'] !== '')
				set_cookie('uiid', $u['iid']);
		}
        Zend_Registry::set('token', $this->_token);
		//user roles only updated for 1 session only
            /*
            set_cookie('roles', $u['roles'], COOKIE_SESSION_TIMEOUT , '/');
            set_cookie('permissions', $this->generateCookiePermissions($u['permissions']), COOKIE_SESSION_TIMEOUT, '/');
            if ($u['id'] > 0)
            {
                $notificationsCount = isset($u['notifications_count']) ? $u['notifications_count'] : 0;
			set_cookie('notifications_count', $notificationsCount);
			
			if (isset($u['notifications_viewed']))
				set_cookie('notifications_viewed', 1, COOKIE_SESSION_TIMEOUT, '/' );
			else
				set_cookie('notifications_viewed', '', -3600);
		}*/		
	}
	
	
	public function generateCookiePermissions($permissions)
	{
		//generate this by doing a "grep CL.permission * -r | grep match|test"
		$allCookieUserPermissions = array ("create_comment", 
			"bypass_captcha", "admin_comment", "admin_node",
			"vote_node", "favorite_node","vote_comment", "viewanswer_quiz");
		$perm = '';
		foreach ($allCookieUserPermissions as $p)
		{
			
			if (strpos($permissions, $p) !== false)
			{
				$perm .= $p . ','; 
			}
		}  
		return $perm;
	}
}
<?php
/**
 * This class is used for all user authentication. Both oauth and normal login
 * It's also used by Cl_Controller_Plugin preDispatch hook to check (be it persistent or not) user authentication
 * 
 * Note that there are 2 kinds of tokens: 
 * 	- cookie token for persistent login
 *  - email token for verifying email
 */
class Cl_Auth_Adapter_PersistentDb implements Zend_Auth_Adapter_Interface
{ 
	private $inputData; //array consiting keys like 'id', 'oauth_id', 'token', 'password'
	
	//used for Zend_Auth_Result;
	private $_user = null;
	private $_code = Zend_Auth_Result::SUCCESS;
    private $_err_code = Zend_Auth_Result::FAILURE_IDENTITY_NOT_FOUND;
	private $_messages = array();
	
	private $_page; //'login' or 'internal_login'. If internal_login, user is automatically logged in by system
	//this happens in cases after activating or something similar

	
	private $_token = ''; //cookie token
	private $_type = '';  //1 is rest | 2 is web 
	
	public function __construct($inputData = null, $page = 'login')
	{
		$this->inputData = $inputData;
		$this->_page = $page;
		$this->_type = is_rest() ? 1 : 2 ;
	}
	
	public function authenticate()
	{
		$inputData = $this->inputData;
		$dao = Dao_User::getInstance();
		if ($this->_page == 'internal_login') //user is automatically logged in
		{
			$r = array('success' =>true, 'result' => $this->inputData);
		}
		else 
		{
    		//STEP 1: Construct condition data to authenticate
            //check persistent login with cookie values : cl_uid, cl_uhash, cl_token
            if (isset($inputData['check_persistent_connection'])) //cookie or REST token
            {
            	if (
    				is_null($uid = get_cookie('uid')) || 
    				is_null($uhash = get_cookie('uhash')) ||
    				is_null($token = get_cookie('token'))
    			)
    			{
    				$this->_messages = array ("Error: No token sent !");
    				return $this->_formatResult();
    			}
    			else //some cookie
    			{
    				if ($uhash != auth_generate_uhash($uid)) 
    				{
    					$this->_messages = array("Wrong pair of uid and uhash");
    				}
    				else 
    				{
    					$this->oldToken = (string)$token;
    					$whereCond = array('id' => $uid, 
    								   'token' => array('$elemMatch' => 
    								   		array(
    								   			'token' => (string)$token,
    								   			'type' => $this->_type
    								   		)) 
    							);
    				}
    			}
            }
           	else
           	{
           		if(!isset($inputData['oauth_type'])) 
            	{
            		if (in_array($this->_page, array('register', 'activate')))
            		{
            		   	$whereCond = array('id' => $inputData['id'], 'pass' => $inputData['pass'],
            		   				  'lname' => $inputData['lname']
            		   			);
            		}
            		else //login
            		{
    		           	$pass = Cl_Dao_Util::computePasswordHash($inputData['pass']);
    		            //$whereCond = array('lname' => $inputData['lname'], 'pass' => $pass);
    		            // login with login name or email ?
    		            $whereCond = array(
    		            		'$or' => array(
    		            				array('lname' => $inputData['lname']), 
    		            				array('mail' => $inputData['lname'])
    		            		),
    		            		'pass' => $pass
    		            );
            		}
            	}
    	        else{
    	        	if (isset($inputData['id']) && $inputData['id'] != '' && !is_null($inputData['id']))
    	        	{
	    	            $whereCond = array("oauth.{$inputData['oauth_type']}.id" => $inputData['id']);
	    	            //TODO: do we need access_token?
	    	            $oauthType = $inputData['oauth_type'];
	    	            //unset($inputData['oauth_type']);
	    	            $oauth_data = $inputData;
    	        	}
    	        	else //somehow authenticate failed with twitter or fb or google...
    	        		return $this->_formatResult();
    	        }
            }
            if (!isset($whereCond))
            {
                return $this->_formatResult();
            }
            $r = $dao->authenticate($whereCond);
        }
        if ($r['success']) {
            //STEP 2: authentication success
            $this->_u = $this->_user = $r['result'];
            $where = array('id' => $this->_user['id']);
            if($this->_token == "" || ($this->_token != $this->oldToken)){
            	//remover token rest
            	$t = $dao->update($where, array('$pull' => array('token' => array('type' => 1))));
            	if(!$t['success'])
            		$this->_messages = array ($t['err']);
            	$this->_token = (string)new MongoId();
            	$token = array(
            			'token' => $this->_token,
            			'ts' => time(),
            			'type' => $this->_type,
            			'expire' => ''
            	);
            	// if tokens number > TOKEN_PERSISTENT_LIMIT then remove first token of web.
            	if(isset($this->_user['token']) && count($this->_user['token']) > TOKEN_PERSISTENT_LIMIT) {
            		foreach($this->_user['token'] as $key => $row){
            			if($row['type'] == 2){
            				unset($this->_user['token'][$key]);
            				break;
            			}
            		}
            		$t = $dao->update($where, array('$set' => array('token' => $this->_user['token'])));
            		if(!$t['success'])
            			$this->_messages = array ($t['err']);
            	}
            	$dataToUpdate = array(
            			'$push' => array('token' => $token),
            			'$set' => array('last_login' => time()),
            	);
            	
            }
            else{ 
            	//user session in web
            	$isExistsTokenRest = false;
            	foreach($this->_user['token'] as $key => $row){
            		if($row['type'] == 2){
            			unset($this->_user['token'][$key]);
            			$isExistsTokenRest = true;
            			break;
            		}
            	}
            	if(!is_rest() && $isExistsTokenRest){
            		$t = $dao->update($where, array('$set' => array('token' => $this->_user['token'])));
            		if(!$t['success'])
            			$this->_messages = array ($t['err']);
            	}
            	
            }
        }
        else //authenticate failed
        {
            //STEP 3: Authentication failed
        	if(isset($inputData['oauth_type'])) //user has successfully authenticated with with oauth
        	//but still failed to authenticate with database
        	//this can only happen in 2 cases
        	//1. Email collision
        	//2. First time login 
        	{
        		// check email address
        		$userExists  = false;
        		//if($inputData['mail'] == $u['oauth']['mail'] then update oauth data for this user
        		$oauthTypeList = array('google', 'yahoo', 'facebook', 'twitter');
        		foreach($oauthTypeList as $type) {
        			$mWhere[] = array('oauth.' . $type . '.mail' => $inputData['mail']);
        		}
        		$mWhere[] = array('mail' => $inputData['mail']);
        		
        		$uWhere = array('$or' => $mWhere);
        		$t = Cl_Dao_Util::getUserDao()->findOne($uWhere);
        		if($t['success'] && $t['count'] > 0 && !is_null($inputData['mail'])) {
        		    //2 cases can happen
        		    //1. Some other user has used this email and not yet activated
        		    // In this case, make user active & disable login by password
        		    // This way the other user would not be able to login by password
        		    
        		    $this->_user = $user = $t['result'];
        		    if ($user['status'] == 'unactivated' )
        		    {
            		    $dataToUpdate = array('$set' => array(
            		        'status' => 'activated'
            		        ),
            		        '$unset' => array('pass' => 1, 'activation_code' => 1)
            		    
            		    );
        		    }
        		    else 
        		    {
            		    //2. This user has used & validated this emal
            		    //In this case, update oauth
            		    $dataToUpdate = array(
            		        '$set' => array("oauth." . $inputData['oauth_type'] => $inputData)
            		    );
        		    }
        		    $this->_token = (string)new MongoId();
        		    $token = array(
        		    		'token' => $this->_token,
        		    		'ts' => time(),
        		    		'type' => $this->_type,
        		    		'expire' => ''
        		    );
        		    
        		    $where = array('id' => $this->_user['id']);
        		    $dataToUpdate['$push'] = array("token" => $token);
        		    
        		    //$dao->update(array('mail' => $inputData['mail']), $updateData);
        		}
        		else {
        			//guest is linking to oauth.
        			//This is a first-time logged in via this oauth id. Now insert new user
        			$newUser = array();
        			if(isset($oauth_data['mail'])) {
        				$newUser["mail"] = $oauth_data['mail'];
        				//unset($oauth_data['mail']);
        			}
        			/*else
        			 $newUser["mail"] = '';*/
        			 
        			$newUser["name"] = $oauth_data['name'];
        			$newUser['avatar'] = $oauth_data['avatar'];
        			$newUser["oauth"] = array($oauthType => $oauth_data);
        			
        			$this->_token = (string)new MongoId();
        			
        			$token = array(
        					'token' => $this->_token,
        					'ts' => time(),
        					'type' => $this->_type,
        					'expire' => ''
        			);
        			
        			$newUser['token'] = array($token);
        			$newUser['status'] = 'activated'; //oauth user should be activated right away
        			$r = $dao->insertUser($newUser);
        			if($r['success'] && isset($r['result']['id'])) {
        				$this->_user = $r['result']; //for cookie
        				Zend_Registry::set('new_registration', true);
        			}
        			else {
        				$this->_messages = array ("Error inserting new oauth user: " . $r['err']);
        			}
        		}
        	}
	        else {
	            //TODO: if the failure is due to unmatched cookie token (cl_token)
	            //insert notif or email them????
	        	$this->_messages = array ("Error: user not found !");
	        }
        }
        //STEP 4: If user needs to update some token, unverified mail...
        //this happens when (authentication suceeds || (fails & logged in user is linking to another oauth))
        if (isset($where) && isset($dataToUpdate)) //needs to update user table
        {
//         	v($where); v($dataToUpdate); die('uuuu');
            $r = $dao->update($where, $dataToUpdate);
            if(!$r['success']) {
            	$this->_messages = array("update user failed");
            }
            else {
            	if(isset($data['mail']))
            		Cl_Notif::getInstance()->markNotifAsRead($u,'', "require_email");
            }
        }
        return $this->_formatResult();
	}
	
	public function clearIdentity()
	{
		$u = Zend_Registry::get('user');
		if ($u['id'] != 0)
		{
    		$token = get_cookie('token');
    		$dataToUpdate = array('$pull' => array('token' => array('token' => (string)$token)));
    		$r = Cl_Dao_Util::getUserDao()->update(array('id' => $u['id']), $dataToUpdate);
    		if(!$r['success'])
    			$this->_messages = array ($r['err']);
		}
		
		//only clear the identity
		set_cookie('token','', -3600);
		set_cookie('roles','', -3600);
		set_cookie('permissions','', -3600);
		set_cookie('uiid','', -3600);
		set_cookie('money','', -3600);
		set_cookie('vmoney','', -3600);
		
		
		//affiliate campaign
		set_cookie('c','', -3600);
		set_cookie('f','', -3600);
		
		//set_cookie('co','', -3600);
		
		$auth = Zend_Auth::getInstance();
        if ($auth->hasIdentity()) {
            $auth->clearIdentity();
        }

        $auth->getStorage()->write($this->_user);
		return $this->_formatResult();
	}

	private function _formatResult()
	{
        if(is_null($this->_user))
        {
            //return new Zend_Auth_Result($this->_err_code, $this->_user, $this->_messages);
            $this->_user = guest_user();
        }
        //$this->_user['avatar'] = $this->_user['avatar'];
        if ($this->_user['id'] != 0)
        //if (!is_guest())
        {
            $this->_user['uhash'] = auth_generate_uhash($this->_user['id']);
        }
        else 
            $this->_user['uhash'] = '';
        
        Zend_Registry::set('user', $this->_user);

		$u['id'] = $this->_user['id'];
		if (isset($this->_user['iid']) && $this->_user['iid'] !== '')
		{
			$u['iid'] = $this->_user['iid'];
		}
		$u['name'] = $this->_user['name'];
		if (isset($this->_user['avatar']))
			$u['avatar'] = $this->_user['avatar'];
		
		$u['uhash'] = $this->_user['uhash'];
		if (isset($this->_user['counter']) && isset($this->_user['counter']['vmoney']))
			$u['vmoney'] = $this->_user['counter']['vmoney'];
		if (isset($this->_user['counter']) && isset($this->_user['counter']['money']))
			$u['money'] = $this->_user['counter']['money'];
				
        if(isset($this->_user['mail']))
            $u['mail'] = $this->_user['mail'];
		$this->setAuthCookie($u);
 		return new Zend_Auth_Result($this->_code, $u, $this->_messages);
	}
	
	public function setAuthCookie($u, $extendExpiryOnly = false)
	{
		//always set uid, uhash
		if (!$extendExpiryOnly)
		{
			set_cookie('uid', $u['id']);
			set_cookie('uname', $u['name']);
			set_cookie('uhash', $u['uhash']);
			set_cookie('token', $this->_token);
			/*
			if (isset($u['money']) && $u['money'] !== '')
				set_cookie('money', $u['money']);

			if (isset($u['vmoney']) && $u['vmoney'] !== '')
				set_cookie('vmoney', $u['vmoney']);
		    */
					
			if (isset($u['iid']) && $u['iid'] !== '')
				set_cookie('uiid', $u['iid']);
		}
        Zend_Registry::set('token', $this->_token);
		//user roles only updated for 1 session only
            /*
            set_cookie('roles', $u['roles'], COOKIE_SESSION_TIMEOUT , '/');
            set_cookie('permissions', $this->generateCookiePermissions($u['permissions']), COOKIE_SESSION_TIMEOUT, '/');
            if ($u['id'] > 0)
            {
                $notificationsCount = isset($u['notifications_count']) ? $u['notifications_count'] : 0;
			set_cookie('notifications_count', $notificationsCount);
			
			if (isset($u['notifications_viewed']))
				set_cookie('notifications_viewed', 1, COOKIE_SESSION_TIMEOUT, '/' );
			else
				set_cookie('notifications_viewed', '', -3600);
		}*/		
	}
<?php
/**
 * This class is used for all user authentication. Both oauth and normal login
 * It's also used by Cl_Controller_Plugin preDispatch hook to check (be it persistent or not) user authentication
 * 
 * Note that there are 2 kinds of tokens: 
 * 	- cookie token for persistent login
 *  - email token for verifying email
 */
class Cl_Auth_Adapter_PersistentDb implements Zend_Auth_Adapter_Interface
{ 
	private $inputData; //array consiting keys like 'id', 'oauth_id', 'token', 'password'
	
	//used for Zend_Auth_Result;
	private $_user = null;
	private $_code = Zend_Auth_Result::SUCCESS;
    private $_err_code = Zend_Auth_Result::FAILURE_IDENTITY_NOT_FOUND;
	private $_messages = array();
	
	private $_page; //'login' or 'internal_login'. If internal_login, user is automatically logged in by system
	//this happens in cases after activating or something similar

	
	private $_token = ''; //cookie token
	private $_type = '';  //1 is rest | 2 is web 
	
	public function __construct($inputData = null, $page = 'login')
	{
		$this->inputData = $inputData;
		$this->_page = $page;
		$this->_type = is_rest() ? 1 : 2 ;
	}
	
	public function authenticate()
	{
		$inputData = $this->inputData;
		$dao = Dao_User::getInstance();
		if ($this->_page == 'internal_login') //user is automatically logged in
		{
			$r = array('success' =>true, 'result' => $this->inputData);
		}
		else 
		{
    		//STEP 1: Construct condition data to authenticate
            //check persistent login with cookie values : cl_uid, cl_uhash, cl_token
            if (isset($inputData['check_persistent_connection'])) //cookie or REST token
            {
            	if (
    				is_null($uid = get_cookie('uid')) || 
    				is_null($uhash = get_cookie('uhash')) ||
    				is_null($token = get_cookie('token'))
    			)
    			{
    				$this->_messages = array ("Error: No token sent !");
    				return $this->_formatResult();
    			}
    			else //some cookie
    			{
    				if ($uhash != auth_generate_uhash($uid)) 
    				{
    					$this->_messages = array("Wrong pair of uid and uhash");
    				}
    				else 
    				{
    					$this->oldToken = (string)$token;
    					$whereCond = array('id' => $uid, 
    								   'token' => array('$elemMatch' => 
    								   		array(
    								   			'token' => (string)$token,
    								   			'type' => $this->_type
    								   		)) 
    							);
    				}
    			}
            }
           	else
           	{
           		if(!isset($inputData['oauth_type'])) 
            	{
            		if (in_array($this->_page, array('register', 'activate')))
            		{
            		   	$whereCond = array('id' => $inputData['id'], 'pass' => $inputData['pass'],
            		   				  'lname' => $inputData['lname']
            		   			);
            		}
            		else //login
            		{
    		           	$pass = Cl_Dao_Util::computePasswordHash($inputData['pass']);
    		            //$whereCond = array('lname' => $inputData['lname'], 'pass' => $pass);
    		            // login with login name or email ?
    		            $whereCond = array(
    		            		'$or' => array(
    		            				array('lname' => $inputData['lname']), 
    		            				array('mail' => $inputData['lname'])
    		            		),
    		            		'pass' => $pass
    		            );
            		}
            	}
    	        else{
    	        	if (isset($inputData['id']) && $inputData['id'] != '' && !is_null($inputData['id']))
    	        	{
	    	            $whereCond = array("oauth.{$inputData['oauth_type']}.id" => $inputData['id']);
	    	            //TODO: do we need access_token?
	    	            $oauthType = $inputData['oauth_type'];
	    	            //unset($inputData['oauth_type']);
	    	            $oauth_data = $inputData;
    	        	}
    	        	else //somehow authenticate failed with twitter or fb or google...
    	        		return $this->_formatResult();
    	        }
            }
            if (!isset($whereCond))
            {
                return $this->_formatResult();
            }
            $r = $dao->authenticate($whereCond);
        }
        if ($r['success']) {
            //STEP 2: authentication success
            $this->_u = $this->_user = $r['result'];
            $where = array('id' => $this->_user['id']);
            if($this->_token == "" || ($this->_token != $this->oldToken)){
            	//remover token rest
            	$t = $dao->update($where, array('$pull' => array('token' => array('type' => 1))));
            	if(!$t['success'])
            		$this->_messages = array ($t['err']);
            	$this->_token = (string)new MongoId();
            	$token = array(
            			'token' => $this->_token,
            			'ts' => time(),
            			'type' => $this->_type,
            			'expire' => ''
            	);
            	// if tokens number > TOKEN_PERSISTENT_LIMIT then remove first token of web.
            	if(isset($this->_user['token']) && count($this->_user['token']) > TOKEN_PERSISTENT_LIMIT) {
            		foreach($this->_user['token'] as $key => $row){
            			if($row['type'] == 2){
            				unset($this->_user['token'][$key]);
            				break;
            			}
            		}
            		$t = $dao->update($where, array('$set' => array('token' => $this->_user['token'])));
            		if(!$t['success'])
            			$this->_messages = array ($t['err']);
            	}
            	$dataToUpdate = array(
            			'$push' => array('token' => $token),
            			'$set' => array('last_login' => time()),
            	);
            	
            }
            else{ 
            	//user session in web
            	$isExistsTokenRest = false;
            	foreach($this->_user['token'] as $key => $row){
            		if($row['type'] == 2){
            			unset($this->_user['token'][$key]);
            			$isExistsTokenRest = true;
            			break;
            		}
            	}
            	if(!is_rest() && $isExistsTokenRest){
            		$t = $dao->update($where, array('$set' => array('token' => $this->_user['token'])));
            		if(!$t['success'])
            			$this->_messages = array ($t['err']);
            	}
            	
            }
        }
        else //authenticate failed
        {
            //STEP 3: Authentication failed
        	if(isset($inputData['oauth_type'])) //user has successfully authenticated with with oauth
        	//but still failed to authenticate with database
        	//this can only happen in 2 cases
        	//1. Email collision
        	//2. First time login 
        	{
        		// check email address
        		$userExists  = false;
        		//if($inputData['mail'] == $u['oauth']['mail'] then update oauth data for this user
        		$oauthTypeList = array('google', 'yahoo', 'facebook', 'twitter');
        		foreach($oauthTypeList as $type) {
        			$mWhere[] = array('oauth.' . $type . '.mail' => $inputData['mail']);
        		}
        		$mWhere[] = array('mail' => $inputData['mail']);
        		
        		$uWhere = array('$or' => $mWhere);
        		$t = Cl_Dao_Util::getUserDao()->findOne($uWhere);
        		if($t['success'] && $t['count'] > 0 && !is_null($inputData['mail'])) {
        		    //2 cases can happen
        		    //1. Some other user has used this email and not yet activated
        		    // In this case, make user active & disable login by password
        		    // This way the other user would not be able to login by password
        		    
        		    $this->_user = $user = $t['result'];
        		    if ($user['status'] == 'unactivated' )
        		    {
            		    $dataToUpdate = array('$set' => array(
            		        'status' => 'activated'
            		        ),
            		        '$unset' => array('pass' => 1, 'activation_code' => 1)
            		    
            		    );
        		    }
        		    else 
        		    {
            		    //2. This user has used & validated this emal
            		    //In this case, update oauth
            		    $dataToUpdate = array(
            		        '$set' => array("oauth." . $inputData['oauth_type'] => $inputData)
            		    );
        		    }
        		    $this->_token = (string)new MongoId();
        		    $token = array(
        		    		'token' => $this->_token,
        		    		'ts' => time(),
        		    		'type' => $this->_type,
        		    		'expire' => ''
        		    );
        		    
        		    $where = array('id' => $this->_user['id']);
        		    $dataToUpdate['$push'] = array("token" => $token);
        		    
        		    //$dao->update(array('mail' => $inputData['mail']), $updateData);
        		}
        		else {
        			//guest is linking to oauth.
        			//This is a first-time logged in via this oauth id. Now insert new user
        			$newUser = array();
        			if(isset($oauth_data['mail'])) {
        				$newUser["mail"] = $oauth_data['mail'];
        				//unset($oauth_data['mail']);
        			}
        			/*else
        			 $newUser["mail"] = '';*/
        			 
        			$newUser["name"] = $oauth_data['name'];
        			$newUser['avatar'] = $oauth_data['avatar'];
        			$newUser["oauth"] = array($oauthType => $oauth_data);
        			
        			$this->_token = (string)new MongoId();
        			
        			$token = array(
        					'token' => $this->_token,
        					'ts' => time(),
        					'type' => $this->_type,
        					'expire' => ''
        			);
        			
        			$newUser['token'] = array($token);
        			$newUser['status'] = 'activated'; //oauth user should be activated right away
        			$r = $dao->insertUser($newUser);
        			if($r['success'] && isset($r['result']['id'])) {
        				$this->_user = $r['result']; //for cookie
        				Zend_Registry::set('new_registration', true);
        			}
        			else {
        				$this->_messages = array ("Error inserting new oauth user: " . $r['err']);
        			}
        		}
        	}
	        else {
	            //TODO: if the failure is due to unmatched cookie token (cl_token)
	            //insert notif or email them????
	        	$this->_messages = array ("Error: user not found !");
	        }
        }
        //STEP 4: If user needs to update some token, unverified mail...
        //this happens when (authentication suceeds || (fails & logged in user is linking to another oauth))
        if (isset($where) && isset($dataToUpdate)) //needs to update user table
        {
//         	v($where); v($dataToUpdate); die('uuuu');
            $r = $dao->update($where, $dataToUpdate);
            if(!$r['success']) {
            	$this->_messages = array("update user failed");
            }
            else {
            	if(isset($data['mail']))
            		Cl_Notif::getInstance()->markNotifAsRead($u,'', "require_email");
            }
        }
        return $this->_formatResult();
	}
	
	public function clearIdentity()
	{
		$u = Zend_Registry::get('user');
		if ($u['id'] != 0)
		{
    		$token = get_cookie('token');
    		$dataToUpdate = array('$pull' => array('token' => array('token' => (string)$token)));
    		$r = Cl_Dao_Util::getUserDao()->update(array('id' => $u['id']), $dataToUpdate);
    		if(!$r['success'])
    			$this->_messages = array ($r['err']);
		}
		
		//only clear the identity
		set_cookie('token','', -3600);
		set_cookie('roles','', -3600);
		set_cookie('permissions','', -3600);
		set_cookie('uiid','', -3600);
		set_cookie('money','', -3600);
		set_cookie('vmoney','', -3600);
		
		
		//affiliate campaign
		set_cookie('c','', -3600);
		set_cookie('f','', -3600);
		
		//set_cookie('co','', -3600);
		
		$auth = Zend_Auth::getInstance();
        if ($auth->hasIdentity()) {
            $auth->clearIdentity();
        }

        $auth->getStorage()->write($this->_user);
		return $this->_formatResult();
	}

	private function _formatResult()
	{
        if(is_null($this->_user))
        {
            //return new Zend_Auth_Result($this->_err_code, $this->_user, $this->_messages);
            $this->_user = guest_user();
        }
        //$this->_user['avatar'] = $this->_user['avatar'];
        if ($this->_user['id'] != 0)
        //if (!is_guest())
        {
            $this->_user['uhash'] = auth_generate_uhash($this->_user['id']);
        }
        else 
            $this->_user['uhash'] = '';
        
        Zend_Registry::set('user', $this->_user);

		$u['id'] = $this->_user['id'];
		if (isset($this->_user['iid']) && $this->_user['iid'] !== '')
		{
			$u['iid'] = $this->_user['iid'];
		}
		$u['name'] = $this->_user['name'];
		if (isset($this->_user['avatar']))
			$u['avatar'] = $this->_user['avatar'];
		
		$u['uhash'] = $this->_user['uhash'];
		if (isset($this->_user['counter']) && isset($this->_user['counter']['vmoney']))
			$u['vmoney'] = $this->_user['counter']['vmoney'];
		if (isset($this->_user['counter']) && isset($this->_user['counter']['money']))
			$u['money'] = $this->_user['counter']['money'];
				
        if(isset($this->_user['mail']))
            $u['mail'] = $this->_user['mail'];
		$this->setAuthCookie($u);
 		return new Zend_Auth_Result($this->_code, $u, $this->_messages);
	}
	
	public function setAuthCookie($u, $extendExpiryOnly = false)
	{
		//always set uid, uhash
		if (!$extendExpiryOnly)
		{
			set_cookie('uid', $u['id']);
			set_cookie('uname', $u['name']);
			set_cookie('uhash', $u['uhash']);
			set_cookie('token', $this->_token);
			/*
			if (isset($u['money']) && $u['money'] !== '')
				set_cookie('money', $u['money']);

			if (isset($u['vmoney']) && $u['vmoney'] !== '')
				set_cookie('vmoney', $u['vmoney']);
		    */
					
			if (isset($u['iid']) && $u['iid'] !== '')
				set_cookie('uiid', $u['iid']);
		}
        Zend_Registry::set('token', $this->_token);
		//user roles only updated for 1 session only
            /*
            set_cookie('roles', $u['roles'], COOKIE_SESSION_TIMEOUT , '/');
            set_cookie('permissions', $this->generateCookiePermissions($u['permissions']), COOKIE_SESSION_TIMEOUT, '/');
            if ($u['id'] > 0)
            {
                $notificationsCount = isset($u['notifications_count']) ? $u['notifications_count'] : 0;
			set_cookie('notifications_count', $notificationsCount);
			
			if (isset($u['notifications_viewed']))
				set_cookie('notifications_viewed', 1, COOKIE_SESSION_TIMEOUT, '/' );
			else
				set_cookie('notifications_viewed', '', -3600);
		}*/		
	}
	
	
	public function generateCookiePermissions($permissions)
	{
		//generate this by doing a "grep CL.permission * -r | grep match|test"
		$allCookieUserPermissions = array ("create_comment", 
			"bypass_captcha", "admin_comment", "admin_node",
			"vote_node", "favorite_node","vote_comment", "viewanswer_quiz");
		$perm = '';
		foreach ($allCookieUserPermissions as $p)
		{
			
			if (strpos($permissions, $p) !== false)
			{
				$perm .= $p . ','; 
			}
		}  
		return $perm;
	}
}
	
	
	public function generateCookiePermissions($permissions)
	{
		//generate this by doing a "grep CL.permission * -r | grep match|test"
		$allCookieUserPermissions = array ("create_comment", 
			"bypass_captcha", "admin_comment", "admin_node",
			"vote_node", "favorite_node","vote_comment", "viewanswer_quiz");
		$perm = '';
		foreach ($allCookieUserPermissions as $p)
		{
			
			if (strpos($permissions, $p) !== false)
			{
				$perm .= $p . ','; 
			}
		}  
		return $perm;
	}
}

