<?php

require_once('lib/googleAuthenticator.php');
$gauth = new GoogleAuthenticator();


 
//LDAP Bind paramters, need to be a administrator AD User account.
$ldap_password = 'password';
$ldap_username = 'admin@your.domain';
$ldap_connection = ldap_connect("your ip of AD");
 
if (FALSE === $ldap_connection){
    // Uh-oh, something is wrong...
	echo 'Unable to connect to the ldap server';
}
 
// We have to set this option for the version of Active Directory we are using.
ldap_set_option($ldap_connection, LDAP_OPT_PROTOCOL_VERSION, 3) or die('Unable to set LDAP protocol version');
ldap_set_option($ldap_connection, LDAP_OPT_REFERRALS, 0); // We need this for doing an LDAP search.
 
if (TRUE === ldap_bind($ldap_connection, $ldap_username, $ldap_password)){
 
	//Your domains DN to query
    $ldap_base_dn = 'OU=Domain Users,DC=your,DC=domain';
	
	//Get standard users and contacts
    $search_filter = '(|(objectCategory=person)(objectCategory=contact))';
	
	//Connect to LDAP
	$result = ldap_search($ldap_connection, $ldap_base_dn, $search_filter);
	
    if (FALSE !== $result){
		$entries = ldap_get_entries($ldap_connection, $result);
		
		// Uncomment the below if you want to write all entries to debug somethingthing 
		//var_dump($entries);
		
		//Create a table to display the output 
		echo '<h2>AD User Results</h2></br>';
		echo '<table border = "1"><tr bgcolor="#cccccc"><td>Username</td><td>GAuth</td><td>E-Mail Address</td><td>QRCode</td><td>distinguishedName</td><td>result</td></tr>';
		
		//For each account returned by the search
		for ($x=0; $x<$entries['count']; $x++){
			
			//
			//Retrieve values from Active Directory
			//
			$LDAP_DN = "";
			
			if (!empty($entries[$x]['distinguishedname'][0])) {
				$LDAP_DN = $entries[$x]['distinguishedname'][0];
				if ($LDAP_DN == "NULL"){
					$LDAP_DN = "";
				}
			}
			 
			
			
			
			//Windows Usernaame
			$LDAP_samaccountname = "";
			
			if (!empty($entries[$x]['samaccountname'][0])) {
				$LDAP_samaccountname = $entries[$x]['samaccountname'][0];
				if ($LDAP_samaccountname == "NULL"){
					$LDAP_samaccountname= "";
				}
			} else {
				//#There is no samaccountname s0 assume this is an AD contact record so generate a unique username
				
				$LDAP_uSNCreated = $entries[$x]['usncreated'][0];
				$LDAP_samaccountname= "CONTACT_" . $LDAP_uSNCreated;
			}
			
			
			//GAuth
			$LDAP_GAuth = "";
			
			if (!empty($entries[$x]['pager'][0])) {
				$LDAP_GAuth = $entries[$x]['pager'][0];
				if ($LDAP_GAuth == "NULL"){
					$LDAP_GAuth = "";
				}
			}
			
			//Email
			$LDAP_Email = "";
			
			if (!empty($entries[$x]['mail'][0])) {
				$LDAP_Email = $entries[$x]['mail'][0];
				if ($LDAP_Email == "NULL"){
					$LDAP_Email = "";
				}
			}
			
			//pokud nenajde nic v pager, tak vygeneruje kod
			if ($LDAP_GAuth == ""){
				$secret = $gauth->createSecret();
				$entry[pager] = $secret;
				$result = ldap_mod_replace($ldap_connection, $LDAP_DN  , $entry);
			} else {
					$result = 'Nothing to do';
			}
						
			//QRcode
			$GPath="<a target='_blank' href='https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/DIGITEQ_2FA:".$LDAP_samaccountname."?secret=".$LDAP_GAuth."&issuer=DIGITEQ_2FA'>QR_Code</a>";
			
			//zapln tabulku
			echo "<tr><td><strong>" . $LDAP_samaccountname ."</strong></td><td>".$LDAP_GAuth."</td><td>".$LDAP_Email."</td><td>".$GPath."</td><td>".$LDAP_DN."</td><td>".$result."</td></tr>";
			
		} //END for loop
	} //END FALSE !== $result
	
	ldap_unbind($ldap_connection); // Clean up after ourselves.
	echo("</table>"); //close the table
 
} //END ldap_bind
 ?>
