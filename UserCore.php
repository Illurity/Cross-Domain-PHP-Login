<?php

session_start();

class UserLogin {

	//Database Connection Variables
	private $database_host = "";
	private $database_username = "";
	private $database_password = "";
	private $database_name = "";
	private $connection;

	public
	function __construct() {

		$this->connectToDatabase();

	}

	//Get the users actual IP
	private function getUserIP() {
		// Get real visitor IP behind CloudFlare network
		if ( isset( $_SERVER[ "HTTP_CF_CONNECTING_IP" ] ) ) {
			$_SERVER[ 'REMOTE_ADDR' ] = $_SERVER[ "HTTP_CF_CONNECTING_IP" ];
			$_SERVER[ 'HTTP_CLIENT_IP' ] = $_SERVER[ "HTTP_CF_CONNECTING_IP" ];
		}
		$client = @$_SERVER[ 'HTTP_CLIENT_IP' ];
		$forward = @$_SERVER[ 'HTTP_X_FORWARDED_FOR' ];
		$remote = $_SERVER[ 'REMOTE_ADDR' ];

		if ( filter_var( $client, FILTER_VALIDATE_IP ) ) {
			$ip = $client;
		} elseif ( filter_var( $forward, FILTER_VALIDATE_IP ) ) {
			$ip = $forward;
		}
		else {
			$ip = $remote;
		}

		return $ip;
	}


	//Connect to the database.
	private function connectToDatabase() {

		$this->connection = mysqli_connect( $this->database_host, $this->database_username, $this->database_password, $this->database_name );

		if ( !$this->isConnected() )
			die( "Error: Failed to connect to database!" );


	}

	//Check we have a connection to the database.
	private function isConnected() {
		if ( isset( $this->connection ) && !mysqli_errno( $this->connection ) )
			return true;
		else
			return false;
	}

	//Login function, mmmmmm beefy.
	public function login( $username, $password ) {

		//Sanitize input.
		$username = strip_tags( stripslashes( mysqli_real_escape_string( $this->connection, $username ) ) );
		$password = strip_tags( stripslashes( mysqli_real_escape_string( $this->connection, $password ) ) );
		$reflink = "http://localhost/cminexus";
		//$reflink = "portal.cminexus.com";
		
		if(isset($_POST["reflink"])) {
			$reflink = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["reflink"])));
		}
		
		//Don't check their shit if they aren't even trying.
		if ( strlen( $username ) >= 4 && strlen( $password ) >= 5 ) {

			if ( $this->userExists( $username ) ) {

				if ( $this->passwordVerified( $username, $password ) ) {

					if ( !$this->isIPBanned( $username ) ) {

						if ( !$this->isAccountLocked( $username ) ) {

							$this->accountVerification( $username );
							$this->turnOnUser($username, $reflink);
							$this->logAction( "$username logged in!" );

						} else {
							die( "Account is locked." );
						}

					} else {
						die( "Ip banned." );
					}

				} else {
					die( "Invalid password." );
				}

			} else {
				die( "user does not exist" );
			}


		} else {
			die( "Please enter your credentials!" );
		}

	}
	
	//TEMP REGISTER
	public function register() {
		
		$fname = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["fname"])));
		$lname = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["lname"])));
		$uname = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["uname"])));
		$email = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["email"])));
		$cemail = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["cemail"])));
		$cname = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["cname"])));
		$addr1 = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["addr1"])));
		$addr2 = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["addr2"])));
		$country = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["country"])));
		$state = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["state"])));
		$city = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["city"])));
		$postcode = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["postcode"])));
		$phone = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["phone"])));
		$password = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["password"])));
		$cpassword = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_POST["cpassword"])));
		
		echo $fname . "<br />";
		echo $lname . "<br />";
		echo $uname . "<br />";
		echo $email . "<br />";
		echo $cemail . "<br />";
		echo $cname . "<br />";
		echo $addr1 . "<br />";
		echo $addr2 . "<br />";
		echo $country . "<br />";
		echo $state . "<br />";
		echo $city . "<br />";
		echo $postcode . "<br />";
		echo $phone . "<br />";
		echo $password . "<br />";
		echo $cpassword . "<br />";
		
		if(strlen($cname) > 1) {
			$accountType = "Corporate";
		} else {
			$accountType = "Personal";
		}
		
		echo $accountType . "<br />";
		
		if($this->isDataFilled($fname, $lname, $uname, $email, $cemail, $addr1, $country, $state, $city, $postcode, $phone, $password, $cpassword)) {
			if(!$this->userExists($uname)) {
				if(!$this->emailInUse($email)) {
					$password = $this->hash($password);
					if($query = mysqli_query
						($this->connection, 
						"INSERT INTO `tblclients`(
								
								`uuid`,
								`firstname`,
								`lastname`,
								`companyname`,
								`username`,
								`email`,
								`address1`,
								`address2`,
								`city`,
								`state`,
								`postcode`,
								`country`,
								`phonenumber`,
								`password`,
								`authmodule`,
								`authdata`,
								`currency`,
								`defaultgateway`,
								`credit`,
								`taxexempt`,
								`latefeeoveride`,
								`overideduenotices`,
								`separateinvoices`,
								`disableautocc`,
								`datecreated`,
								`notes`,
								`billingcid`,
								`securityqid`,
								`securityqans`,
								`groupid`,
								`cardtype`,
								`cardlastfour`,
								`cardnum`,
								`startdate`,
								`expdate`,
								`issuenumber`,
								`bankname`,
								`banktype`,
								`bankcode`,
								`bankacct`,
								`gatewayid`,
								`lastlogin`,
								`ip`,
								`host`,
								`status`,
								`language`,
								`pwresetkey`,
								`emailoptout`,
								`overrideautoclose`,
								`allow_sso`,
								`email_verified`,
								`created_at`,
								`updated_at`,
								`pwresetexpiry`,
								`account_blocked`
						) VALUES(
								 
								'', 
								'$fname',
								'$lname',
								'$cname',
								'$uname',
								'$email',
								'$addr1',
								'$addr2',
								'$city',
								'$state',
								'$postcode',
								'$country',
								'$phone',
								'$password',
								'',
								'',
								'1',
								'', 
								'0',
								'0',
								'0',
								'0',
								'0',
								'0',
								'".date("Y-m-d", time())."',
								'',
								'0',
								'0',
								'',
								'$accountType',
								'',
								'',
								'',
								'',
								'',
								'',
								'',
								'',
								'',
								'',
								'',
								'".date("Y-m-d H:i:s", time())."',
								'".$this->getUserIP()."',
								'".$this->getUserIP()."',
								'Active',
								'',
								'',
								'0',
								'0',
								'1',
								'0',
 								'".date("Y-m-d H:i:s", time())."', 
 								'".date("Y-m-d H:i:s", time())."', 
								'0000-00-00 00:00:00',
								'0'
						)"
					)) {
						echo "User registered successfully";
					} else {
						echo "Failed to login: " . mysqli_error($this->connection);
					}
				
				} else {
					die("That email is already in use!");
				}
			} else {
				die("That username is already in use!");
			}
		} else {
			die("Please fill out all fields.");
		}
		
	}
	
	private function emailInUse($email) {
		if(mysqli_num_rows(mysqli_query($this->connection, "SELECT NULL FROM `tblclients` WHERE `email` = '$email'")) == 1)
			return true;
		else
			return false;
	} 
	
	//DONT LOOK AT THIS 'tis shameful.                          
	private function isDataFilled($fname, $lname, $uname, $email, $cemail, $addr1, $country, $state, $city, $postcode, $phone, $password, $cpassword) {
		if(strlen($fname) > 1 && strlen($lname) > 1) {
			if(strlen($uname) > 3) {
				if(filter_var($email, FILTER_VALIDATE_EMAIL)) {
					if($email === $cemail) {
						if(strlen($addr1) > 3) {
							if(strlen($country) > 3) {
								if(strlen($state) > 1) {
									if(strlen($city) > 3) {
										if(is_numeric($postcode)) {
	/*If I was more creative I could   */   if(strlen($phone) > 5) {
	/*Draw in this                    */   		if(strlen($password) > 4 && strlen($cpassword)) {
	/*Gross mountain of if statements*/				if($password === $cpassword) {
														return true;
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		return false;
	}
	//Alright you can open your eyes again.
	
	private function turnOnUser($username, $reflink) {
		$link = $this->generateSession($username, $reflink);
		echo "Will send to: " . $link;
		header("Location: $link");
		
	}
	
	private function generateSession($username, $reflink) {
		
		$_SESSION["nexus"]["xid"] = array();
		$xid = md5(uniqid(mt_rand(), true));
		$_SESSION["nexus"]["xid"][$xid] = "$username#".$this->getUserIP()."#".$_SERVER["HTTP_USER_AGENT"]."";
		$token = session_id();
		if(!$query = mysqli_query($this->connection, "INSERT INTO `session_c` (`username`, `auth`, `tkn`, `expires`) VALUES('".$username."', '".$token."', '".$xid."', '". strtotime("+30 minutes", time()) ."')")) {
			echo mysqli_error($this->connection);
		}
		$var = array('xid' => $xid);
		return $reflink . "/auth.php?" . http_build_query($var);
		
	}

	private function verifyRecoveryCode( $code ) {
		if(isset($_SESSION["nexus"]["username"])) {
			
			$username = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_SESSION["nexus"]["username"])));
			$code = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $code)));
			
			$query = mysqli_query($this->connection, "SELECT NULL FROM `tblclients` WHERE `username` = '".$username."' AND `recovery_code` = '".$code."' LIMIT 1");
			if(mysqli_num_rows($query) == 1) {
				mysqli_query($this->connection, "UPDATE `tblclients` SET `account_blocked` = '0' WHERE `username` = '".$username."' LIMIT 1");
				$this->sendUserHome();
				return true;
			} else
				return false;
			
		} else
			header("Location: Login.php");
	}
	
	private function accountVerification( $username ) {
		
		$currentIP = $this->getUserIP();
		
		$query = mysqli_query($this->connection, "SELECT `ip` FROM `tblclients` WHERE `username` = '$username' LIMIT 1");
		$row = mysqli_fetch_assoc($query);
		$lastIP = $row["ip"];
		
		if($currentIP != $lastIP) {
		
			mysqli_query( $this->connection, "UPDATE `tblclients` SET `account_blocked` = '1' WHERE `username` = '$username'" );

			$code = mysqli_real_escape_string( $this->connection, $this->generateRecoveryCode() );

			mysqli_query( $this->connection, "UPDATE `tblclients` SET `recovery_code` = '" . $code . "' WHERE `username` = '$username' LIMIT 1" );

			$_SESSION["nexus"]["username"] = $username;
			
			echo $currentIP . " | " . $lastIP . " needs redirect.";
			
			//header("Location: verify.php");
			
		}

	}

	private function generateRecoveryCode() {
		return $this->hash( time() . "-($" . $username . "$)-" );
	}

	private function logAction( $string ) {
		$string = strip_tags( stripslashes( mysqli_real_escape_string( $this->connection, $string ) ) );
		mysqli_query( $this->connection, "INSERT INTO `action_logs` VALUES('', '" . time() . "', '" . $string . "')" );
	}

	//Check the user actually exists
	private function userExists( $username ) {

		$query = mysqli_query( $this->connection, "SELECT NULL FROM `tblclients` WHERE `username` = '" . $username . "' LIMIT 1" );
		if ( mysqli_num_rows( $query ) == 1 )
			return true;
		else
			return false;

	}

	//Check the user's password
	private function passwordVerified( $username, $password ) {

		$password = $this->hash( $password );
		$query = mysqli_query( $this->connection, "SELECT NULL FROM `tblclients` WHERE `username` = '" . $username . "' AND password = '" . $password . "' LIMIT 1" );
		if ( mysqli_num_rows( $query ) == 1 )
			return true;
		else
			return false;

	}

	//Check if the account is locked
	private function isAccountLocked( $username ) {

		$query = mysqli_query( $this->connection, "SELECT `account_blocked` FROM `tblclients` WHERE `username` = '" . $username . "' LIMIT 1" );
		$row = mysqli_fetch_assoc( $query );
		$account_locked = $row[ "account_blocked" ];

		if ( $account_locked != 0 )
			return true;
		else
			return false;

	}

	//Check if the IP is banned.
	private function isIPBanned( $username ) {

		$query = mysqli_query( $this->connection, "SELECT * FROM `tblbannedips` WHERE `ip` = '" . $this->getUserIP() . "' LIMIT 1" );

		if ( mysqli_num_rows( $query ) == 1 ) {

			$row = mysqli_fetch_assoc( $query );

			//If now > ban expiration, remove ban.
			if ( time() > $row[ "date_expire" ] ) {

				//User's ban has expired. Remove it.
				mysqli_query( $this->connection, "DELETE FROM `tblbannedips` WHERE `id` = '" . $row[ "id" ] . "'" );
				return false;

			} else {
				//User's IP is banned. Create a cookie to lock other accounts they have access to.
				mysqli_query( $this->connection, "UPDATE `tblclients` SET `account_blocked` WHERE `username` = '" . $username . "'" );
				return true;
			}

		}

	}

	private function hash( $text ) {
		$hashA = "a4c4d72cc9492fffe7c7c3cfcad98b41";
		$hashB = "70e6032ea9974c337c9ec6695277dcb7";
		return md5( sha1( $hashA . $text . $hashB ) );
	}

}

$Login = new UserLogin();
if ( isset( $_POST[ "username" ] ) && isset( $_POST[ "password" ] ) ) {
	$Login->login( $_POST[ "username" ], $_POST[ "password" ] );
}

if(isset($_POST["register"])) {
	$Login->register();
}

?>
<html>

<body>
	<form action="" method="POST">
		<input type="hidden" name="refLink" value="<?php echo $_GET["refLink"]; ?>" />
		<input type="text" name="username" placeholder="Username"/><br/>
		<input type="password" name="password" placeholder="Password"/><br/>
		<input type="submit" name="login" value="Login"/>
	</form>
	<hr>
<form action="" method="POST">
  <table>
			<tr>
				<td><input type="text" name="fname" placeholder="First Name" /></td>
				<td><input type="text" name="lname" placeholder="Last Name" /></td>
			</tr>
			<tr>
				<td colspan="2"><input type="text" name="uname" placeholder="Username" style="width:100%;"/></td>
			</tr>
			<tr>
				<td><input type="text" name="email" placeholder="Email" /></td>
				<td><input type="text" name="cemail" placeholder="Confirm Email" /></td>
			</tr>
			<tr>
				<td colspan="2"><input type="text" name="cname" placeholder="Company Name" style="width:100%;"/></td>
			</tr>
			<tr>
				<td><input type="text" name="addr1" placeholder="Address 1" /></td>
				<td><input type="text" name="addr2" placeholder="Address 2" /></td>
			</tr>
			<tr>
				<td><input type="text" name="country" placeholder="Country" /></td>
				<td><input type="text" name="state" placeholder="State" /></td>
			</tr>
			<tr>
				<td><input type="text" name="city" placeholder="City" /></td>
				<td><input type="text" name="postcode" placeholder="Postcode" /></td>
			</tr>
			<tr>
				<td colspan="2"><input type="text" name="phone" placeholder="Phone Number" style="width:100%;" /></td>
			</tr>
	  		<tr>
				<td><input type="password" name="password" placeholder="Password" /></td>
				<td><input type="password" name="cpassword" placeholder="Confirm Password" /></td>
			</tr>
			<tr>
				<td colspan="2"><input type="submit" name="register" value="Register" style="width:100%;" /></td>
			</tr>
		</table>
  </form>
</body>
</html>