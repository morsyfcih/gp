<?php

require_once 'C:/xampp/htdocs/qatra_services/include/DbHandler.php';
require_once 'C:/xampp/htdocs/qatra_services/include/PassHash.php';
require 'C:/xampp/htdocs/qatra_services/libs/Slim/Slim.php';

\Slim\Slim::registerAutoloader();

$app = new \Slim\Slim();

// User id from db - Global Variable
$user_id = NULL;

/**
 * Adding Middle Layer to authenticate every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticate(\Slim\Route $route) {
    // Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();

    // Verifying Authorization Header
    if (isset($headers['Authorization'])) {
        $db = new DbHandler();

        // get the api key
        $api_key = $headers['Authorization'];
        // validating api key
        if (!$db->isValidApiKey($api_key)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Access Denied. Invalid Api key";
            echoRespnse(401, $response);
            $app->stop();
        } else {
            global $user_id;
            // get user primary key id
            $user_id = $db->getUserId($api_key);
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = "Api key is misssing";
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * ----------- METHODS WITHOUT AUTHENTICATION ---------------------------------
 */
/**
 * User Registration
 * url - /register
 * method - POST
 * params - name, email, password
 */
$app->post('/register', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('name', 'email', 'password' ,'age', 'username', 'location' ,'blood_type', 'gendre', 'phone'));

            $response = array();

            // reading post params
            $name = $app->request->post('name');
            $email = $app->request->post('email');
            $password = $app->request->post('password');
            $age = $app->request->post('age');
            $username = $app->request->post('username');
            $location = $app->request->post('location');
            $blood_type = $app->request->post('blood_type');
            $gendre = $app->request->post('gendre');
            $phone = $app->request->post('phone');
               
         // validating email address
            validateEmail($email);

            $db = new DbHandler();
            $res = $db->createUser($name, $email, $password);

            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            // echo json response
            echoRespnse(201, $response);
        });

/**
 * User Login
 * url - /login
 * method - POST
 * params - email, password
 */
$app->post('/login', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('email', 'password'));

            // reading post params
            $email = $app->request()->post('email');
            $password = $app->request()->post('password');
            $response = array();

            $db = new DbHandler();
            // check for correct email and password
            if ($db->checkLogin($email, $password)) {
                // get the user by email
                $user = $db->getUserByEmail($email);

                if ($user != NULL) {
                    $response["error"] = false;
                    $response['name'] = $user['name'];
                    $response['email'] = $user['email'];
                    $response['age'] = $user['age'];
                    $response['location'] = $user['location'];
                    $response['blood_type'] = $user['blood_type'];
                    $response['gendre'] = $user['gendre'];
                    $response['phone'] = $user['phone'];
                    $response['apiKey'] = $user['api_key'];
                    $response['createdAt'] = $user['created_at'];
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "An error occurred. Please try again";
                }
            } else {
                // user credentials are wrong
                $response['error'] = true;
                $response['message'] = 'Login failed. Incorrect credentials';
            }

            echoRespnse(200, $response);
        });

/*
 * ------------------------ METHODS WITH AUTHENTICATION ------------------------
 */

/**
 * Listing all tasks of particual user
 * method GET
 * url /requests          
 */
$app->get('/requests', 'authenticate', function() {
            global $user_id;
            $response = array();
            $db = new DbHandler();

            // fetching all user tasks
            $result = $db->getAllUserRequests($user_id);
            
            if ($result != NULL) {
            
            	$items = array();
            	
            	foreach ($result as $rez) {
            		$response["error"] = false;
            		$response["id"] = $rez["id"];
            		$response["description"] = $rez["description"];
            		$response["status"] = $rez["status"];
            		$response["createdAt"] = $rez["created_at"];	
            		
            		$items[] = $response;
            	}
            
            	echoRespnse(200, $items);
            } else {
            	$response["error"] = true;
            	$response["message"] = "The requested resource doesn't exists";
            	echoRespnse(404, $response);
            }
        });

/**
 * Listing single task of particual user
 * method GET
 * url /requests/:id
 * Will return 404 if the requests doesn't belongs to user
 */
$app->get('/requestss/:id', 'authenticate', function($task_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();
 
            // fetch request
            $result = $db->getTask($request_id, $user_id);
 
            if ($result != NULL) {
                $response["error"] = false;
                $response["id"] = $result["id"];
                $response["description"] = $result["description"];
                $response["status"] = $result["status"];
                $response["createdAt"] = $result["created_at"];
                echoRespnse(200, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "The requested resource doesn't exists";
                echoRespnse(404, $response);
            }
        });
/**
 * Creating new task in db
 * method POST
 * params - name
 * url - /requests/
 */
$app->post('/requests', 'authenticate', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('description'));

            $response = array();
            $description = $app->request->post('description');

            global $user_id;
            $db = new DbHandler();

            // creating new request
            $request_id = $db->createTask($user_id, $description);

            if ($reques_id != NULL) {
                $response["error"] = false;
                $response["message"] = "Task created successfully";
                $response["request_id"] = $reques_id;
                echoRespnse(201, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "Failed to create task. Please try again";
                echoRespnse(200, $response);
            }            
        });

/**
 * Updating existing request
 * method PUT
 * params request, status
 * url - /requests/:id
 */
$app->put('/requests/:id', 'authenticate', function($request_id) use($app) {
            // check for required params
            verifyRequiredParams(array('description', 'status'));

            global $user_id;            
            $description = $app->request->put('description');
            $status = $app->request->put('status');

            $db = new DbHandler();
            $response = array();

            // updating request
            $result = $db->updateRequest($user_id, $request_id, $description, $status);
            if ($result) {
                // request updated successfully
                $response["error"] = false;
                $response["message"] = "Request updated successfully";
            } else {
                // request failed to update
                $response["error"] = true;
                $response["message"] = "request failed to update. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Deleting request. Users can delete only their requests
 * method DELETE
 * url /requests
 */
$app->delete('/requests/:id', 'authenticate', function($request_id) use($app) {
            global $user_id;

            $db = new DbHandler();
            $response = array();
            $result = $db->deleteRequest($user_id, $request_id);
            if ($result) {
                // request deleted successfully
                $response["error"] = false;
                $response["message"] = "request deleted succesfully";
            } else {
                // request failed to delete
                $response["error"] = true;
                $response["message"] = "request failed to delete. Please try again!";
            }
            echoRespnse(200, $response);
        });

/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }

    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response["error"] = true;
        $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Validating email address
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = 'Email address is not valid';
        echoRespnse(400, $response);
        $app->stop();
    }
}

/**
 * Echoing json response to client
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoRespnse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);

    // setting response content type to json
    $app->contentType('application/json');

    echo json_encode($response);
}

$app->run();
?>