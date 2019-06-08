function getGAuth($username){
//LDAP Bind paramters, need to be a normal AD User account.
$ldap_password = 'password';
$ldap_username = 'ldap user with only domain users rights';
$ldap_connection = ldap_connect("IP of your AD/RODC");
 
if (FALSE === $ldap_connection){
    // Uh-oh, something is wrong...
	echo 'Unable to connect to the ldap server';
}
// We have to set this option for the version of Active Directory we are using.
ldap_set_option($ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3) or die('Unable to set LDAP protocol version');
ldap_set_option($ldap_connection, LDAP_OPT_REFERRALS, 0); // We need this for doing an LDAP search.
if (TRUE === ldap_bind($ldap_connection, $ldap_username, $ldap_password)){
    $ldap_base_dn = 'OU=Domain Users,DC=your domain,DC=end';
	$search_filter = '(sAMAccountName='.$username.')';
	$result = ldap_search($ldap_connection, $ldap_base_dn, $search_filter);
	
    if (FALSE !== $result){
		$entries = ldap_get_entries($ldap_connection, $result);
		for ($x=0; $x<$entries['count']; $x++){
			//GAuth
			$LDAP_GAuth = "";
			
			if (!empty($entries[$x]['pager'][0])) {
				$LDAP_GAuth = $entries[$x]['pager'][0];
				if ($LDAP_GAuth == "NULL"){
					$LDAP_GAuth = "";
				}
			}
			
		} //END for loop
	} //END FALSE !== $result
	
	ldap_unbind($ldap_connection); // Clean up after ourselves.

} //END ldap_bind
return $LDAP_GAuth;
} 
//------------------------------------------------------
// Include config file
require_once("../config.php");

// Allow included script to be included from this script
define('INCLUSION_ENABLED',true);

//-----------------------------------------------------
// Sending no-cache headers
header( 'Cache-Control: no-store, no-cache, must-revalidate' );
header( 'Cache-Control: post-check=0, pre-check=0', false );
header( 'Pragma: no-cache' );

//------------------------------------------------------
// If any form variable is missing, just display the login page
if (!isset($_POST["username"]) || !isset($_POST["password"]) || !isset($_POST["token"])) {
	require_once("loginForm.php");
}
else {
    //------------------------------------------------------
    // Retrieve and store form parameters
    $username = htmlspecialchars($_POST["username"], ENT_QUOTES);
    //$password = $_POST["password"];
    $token = $_POST["token"];
    
    //-----------------------------------------------------
    // Import database manager library
		//-require_once(DBMANAGER_LIB);
    try {
    	// Create the DB manager object
    	//-$dbManager = new DBManager(USER_SQL_DATABASE_FILE);
    	
    	// Retrieve the password hash and stored Google Auth secret for this user
	    $result = getGAuth($username);
		if ($result == '-'){
	    	$error = "[ERROR] Unknown user";
	    } else {
	    	// Import the GoogleAuth library and create a GoogleAuth object
		    require_once(GAUTH_LIB);
		    $gauth = new GoogleAuthenticator();
	    	
	    	// Checking token
	    	if (!($gauth->verifyCode($result,$token))) {
	   			$error = "[ERROR] Authentication failed";
				//error_log("Secret false");
	       	} else {
	       		$isAdmin = 0;
	       	}
	    }
	    
	    //$dbManager->close();
	    	
    	//--------------------------------------------------
	    // Login successful - let's proceed
	    if (!isset($error)) {
	        //--------------------------------------------------
	        // Creating a session to persist the authentication
	        session_name(SESSION_NAME);
	        session_cache_limiter('private_no_expire');
	        
	        // Session parameters :
	        // - Timelife of of the whole browser session
	        // - Valid for all path on the domain, for this FQDN only
	        // - Ensure Cookies are not available to Javascript
	        // - Cookies are sent on https only
	        $domain = ($_SERVER['HTTP_HOST'] !== 'localhost') ? $_SERVER['SERVER_NAME'] : false;
	        session_set_cookie_params (0, "/", $domain, true, true);
	    
	        // Create a session
	        session_start();
	        
	        $_SESSION["authenticated"] = true;
	        $_SESSION["username"] = $username;
	        $_SESSION["isAdmin"] = ($isAdmin === 1)? true: false;
	        
	        //--------------------------------------------------
	        // Checking which URL we should redirect the user to
	        if (isset($_GET['from'])) {
	        	$from = $_GET['from'];
			if (preg_match('#^(?:https?:)?//#', $_GET['from'], $m)) {
				$url = parse_url($_GET['from']);
				$from = $url['path'] . (!empty($url['query']) ? '?' . $url['query'] : '') . (!empty($url['fragment']) ? '#' . $url['fragment'] : '');
			}
	            $redirectTo = ((isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] === "on")? "https://" : "http://").$_SERVER["SERVER_NAME"].":".$_SERVER["SERVER_PORT"].$from;
				//$redirectTo = $_REQUEST["from"];
				
			}
	        else {
	            $redirectTo = AUTH_SUCCEED_REDIRECT_URL;
	        }
			error_log("redirect> :".$redirectTo);
	        header("Location: ".$redirectTo,true,302);
			//header("Location: ".$redirectTo);
		}
    	else {
    	    http_response_code(403);
        	require_once("loginForm.php");   
    	}
    } catch (Exception $e) {
    	$error = "[ERROR] Cannot open user database file";
    	require_once("loginForm.php");
    }
}
?>
