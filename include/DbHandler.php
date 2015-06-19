<?php

/**
 * Class to handle all db operations
 * This class will have CRUD methods for database tables
 *
 
 */
class DbHandler {

    private $conn;

    function __construct() {
        require_once dirname(__FILE__) . '/DbConnect.php';
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }

    /* ------------- `users` table method ------------------ */

    /**
     * Creating new user
     * @param String $name User full name
     * @param String $email User login email id
     * @param String $password User login password
     */
    public function createUser($name, $email, $password ,$phone , $blood_type , $username , $location ,$age , $gender ) {
        require_once 'PassHash.php';
        $response = array();

        // First check if user already existed in db
        if (!$this->isUserExists($email)) {
            // Generating password hash
            $password_hash = PassHash::hash($password);

            // Generating API key
            $api_key = $this->generateApiKey();

            // insert query
            $stmt = $this->conn->prepare("INSERT INTO users(name, email, password_hash, api_key, status , username , age , gender , blood_type , location , phone)"
                    . "                                values(?, ?, ?, ?, 1 , ? , ? , ? , ? , ? , ?)");
            $stmt->bind_param("ssss", $name, $email, $password_hash, $api_key,$phone , $blood_type , $username , $location ,$age , $gender);

            $result = $stmt->execute();

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return USER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return USER_CREATE_FAILED;
            }
        } else {
            // User with same email already existed in the db
            return USER_ALREADY_EXISTED;
        }

        return $response;
    }

    /**
     * Checking user login
     * @param String $email User login email id
     * @param String $password User login password
     * @return boolean User login status success/fail
     */
    public function checkLogin($email, $password) {
        // fetching user by email
        $stmt = $this->conn->prepare("SELECT password_hash FROM users WHERE email = ?");

        $stmt->bind_param("s", $email);

        $stmt->execute();

        $stmt->bind_result($password_hash);

        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            // Found user with the email
            // Now verify the password

            $stmt->fetch();

            $stmt->close();

            if (PassHash::check_password($password_hash, $password)) {
                // User password is correct
                return TRUE;
            } else {
                // user password is incorrect
                return FALSE;
            }
        } else {
            $stmt->close();

            // user not existed with the email
            return FALSE;
        }
    }

    /**
     * Checking for duplicate user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    private function isUserExists($email) {
        $stmt = $this->conn->prepare("SELECT id from users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getUserByEmail($email) {
        $stmt = $this->conn->prepare("SELECT name, email, api_key, status, created_at FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            // $user = $stmt->get_result()->fetch_assoc();
            $stmt->bind_result($name, $email, $api_key, $status, $created_at);
            $stmt->fetch();
            $user = array();
            $user["name"] = $name;
            $user["email"] = $email;
            $user["api_key"] = $api_key;
            $user["status"] = $status;
            $user["created_at"] = $created_at;
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user api key
     * @param String $user_id user id primary key in user table
     */
    public function getApiKeyById($user_id) {
        $stmt = $this->conn->prepare("SELECT api_key FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            // $api_key = $stmt->get_result()->fetch_assoc();
            // TODO
            $stmt->bind_result($api_key);
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user id by api key
     * @param String $api_key user api key
     */
    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT id FROM users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $stmt->bind_result($user_id);
            $stmt->fetch();
            // TODO
            // $user_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }

    /**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isValidApiKey($api_key) {
        $stmt = $this->conn->prepare("SELECT id from users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Generating random Unique MD5 String for user Api key
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }

    /* ------------- `requests` table method ------------------ */

    /**
     * Creating new task
     * @param String $user_id user id to whom task belongs to
     * @param String $task task text
     */
    public function createRequest($user_id, $description) {
        $stmt = $this->conn->prepare("INSERT INTO requests(description) VALUES(?)");
        $stmt->bind_param("s", $description);
        $result = $stmt->execute();
        $stmt->close();

        if ($result) {
            // request row created
            // now assign the request to user
            $new_request_id = $this->conn->insert_id;
            $res = $this->createUserRequest($user_id, $new_request_id);
            if ($res) {
                // request created successfully
                return $new_request_id;
            } else {
                // request failed to create
                return NULL;
            }
        } else {
            // request failed to create
            return NULL;
        }
    }

    /**
     * Fetching single request
     * @param String $request_id id of the request
     */
    public function getRequest($request_id, $user_id) {
        $stmt = $this->conn->prepare("SELECT r.id, r.description, r.status, r.created_at from requests r, user_requests ur WHERE r.id = ? AND ur.request_id = r.id AND ur.user_id = ?");
        $stmt->bind_param("ii", $request_id, $user_id);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($id, $description, $status, $created_at);
            // TODO
            // $request = $stmt->get_result()->fetch_assoc();
            $stmt->fetch();
            $res["id"] = $id;
            $res["description"] = $description;
            $res["status"] = $status;
            $res["created_at"] = $created_at;
            $stmt->close();
            return $res;
        } else {
            return NULL;
        }
    }

    
public function getAllUserRequests($user_id) {
		$stmt = $this->conn->prepare("SELECT r.* FROM requests r, user_requests ur WHERE r.id = ur.request_id AND ur.user_id = ?");
		$stmt->bind_param("i", $user_id);
		if ($stmt->execute()) {
			$items = $res = array();
			
			$stmt->bind_result($id, $description, $status, $created_at);
			
			while ($stmt->fetch()) {
				$res["id"] = $id;
				$res["description"] = $description;
				$res["status"] = $status;
				$res["created_at"] = $created_at;
				
				$items[] = $res;
			}
			
			$stmt->close();
			
			return $items;
			
		} else {
			return NULL;
		}
	}




    /**
     * Updating request
     * @param String $request_id id of the task
     * @param String $request request text
     * @param String $status request status
     */
    public function updateRequest($user_id, $request_id, $description, $status) {
        $stmt = $this->conn->prepare("UPDATE requests r, user_requests ur set r.description = ?, r.status = ? WHERE r.id = ? AND r.id = ur.request_id AND ur.user_id = ?");
        $stmt->bind_param("siii", $description, $status, $request_id, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /**
     * Deleting a request
     * @param String $request_id id of the request to delete
     */
    public function deleteRequest($user_id, $request_id) {
        $stmt = $this->conn->prepare("DELETE r FROM requests r, user_requests ur WHERE r.id = ? AND ur.request_id = r.id AND ur.user_id = ?");
        $stmt->bind_param("ii", $request_id, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /* ------------- `user_request` table method ------------------ */

    /**
     * Function to assign a request to user
     * @param String $user_id id of the user
     * @param String $request_id id of the task
     */
    public function createUserRequest($user_id, $request_id) {
        $stmt = $this->conn->prepare("INSERT INTO user_requests(user_id, request_id) values(?, ?)");
        $stmt->bind_param("ii", $user_id, $request_id);
        $result = $stmt->execute();

        if (false === $result) {
            die('execute() failed: ' . htmlspecialchars($stmt->error));
        }
        $stmt->close();
        return $result;
    }

}

?>
