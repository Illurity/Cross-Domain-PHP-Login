<?php
	
	class CrossDomain {
		
		private $database_host = "";
		private $database_username = "";
		private $database_password = "";
		private $database_name = "";
		private $connection;
		
		private $xid;
		
		private $username;
		private $sessionIP;
		private $sessionAgent;
		
		public function __construct() {
			if(isset($_GET["xid"])) {
				$this->connnectToDatabase();
				$this->xid = strip_tags(stripslashes(mysqli_real_escape_string($this->connection, $_GET["xid"])));
				$this->generateSession();
				$this->hijackCheck();
				$this->regenSession();
				$this->cleanUp();
			}

		}
		
		private function connnectToDatabase() {
			$this->connection = mysqli_connect($this->database_host, $this->database_username, $this->database_password, $this->database_name);
		}
		
		private function generateSession() {
			
			//Create the session from the database's sessions ID linked with the GET XID
			$query = mysqli_query($this->connection, "SELECT `auth` FROM `session_c` WHERE `tkn` = '".$this->xid."'");
			
			if(mysqli_num_rows($query) == 1) {
				
				$row = mysqli_fetch_assoc($query);
				$sessionId = $row["auth"];

				session_id($sessionId);
				session_start();

				$varArray = explode("#", $_SESSION["nexus"]["xid"]);
				$_SESSION["nexus"]["udata"] = serialize($varArray);
				
			} else {
				
				header("Location: UserCore.php");
				
			}
			
		}
		
		private function hijackCheck() {
			//Check IP and agent sent with session and make sure they haven't changed.
			list($username, $sessionIP, $sessionAgent) = explode('#', $_SESSION["nexus"]["xid"]);
			$this->username = $username;
			$this->sessionIP = $sessionIP;
			$this->sessionAgent = $sessionAgent;
			if($this->sessionIP != $this->getUserIP() || $this->sessionAgent != $_SERVER["HTTP_USER_AGENT"]) {
				unset($_SESSION["nexus"]["xid"]);
				session_destroy();
				//Maybe redirect to error page?
			}
		}
		
		private function regenSession() {
			//Create a new session so we can later remove the XID data.
			$userData = array($this->username, $this->sessionIP, $this->sessionAgent);
			$_SESSION["nexus"]["data"] = serialize($userData);
		}
		
		private function cleanUp() {
			//Delete everything related to the XID so the session can't be duplicated by session highjack.
			if(isset($_SESSION["nexus"]["xid"])) {
				mysqli_query($this->connection, "DELETE FROM `session_c` WHERE `tkn` = '".$this->xid."'");
				//Uncomment when live
				unset($_SESSION["nexus"]["xid"]);
				//Then redirect to a home page because we don't want to stay in this file.
				//header("Location: home");
				//Later add the home variable to the data that is sent in the session so we can redirect back to the previous page.
			}
		}
		
		private function getUserIP() {
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
		
	}

	$CrossDomain = new CrossDomain();
	

?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Untitled Document</title>
</head>
<body>
	<?php
	$udata2 = unserialize($_SESSION["nexus"]["udata"]);
	echo "Your Info:<br />Username: {$udata2[0]}<br />IP: {$udata2[1]}<br />Agent: {$udata2[2]}";
	?>
</body>
</html>
