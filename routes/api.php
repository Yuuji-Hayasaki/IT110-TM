<?php

// Function to establish database connection (Replace with your database credentials)
function connectDB() {
    $servername = "localhost"; // Replace with your MySQL server name
    $username = "root"; // Replace with your MySQL username
    $password = ""; // Replace with your MySQL password
    $dbname = "TaskMaster"; // Replace with your MySQL database name

    $conn = new mysqli($servername, $username, $password, $dbname);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    return $conn;
}

// Handle POST requests
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Check if action is provided
    if (isset($_POST['action'])) {
        $action = $_POST['action'];

        // Handle login action
        if ($action === 'login') {
            if (isset($_POST['email']) && isset($_POST['password'])) {
                $email = $_POST['email'];
                $password = $_POST['password'];

                $conn = connectDB();
                $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $result = $stmt->get_result();

                if ($result->num_rows > 0) {
                    $user = $result->fetch_assoc();
                    if (password_verify($password, $user['password'])) {
                        // Login successful
                        echo json_encode(array('status' => 'success', 'message' => 'Login successful'));
                    } else {
                        // Invalid password
                        echo json_encode(array('status' => 'error', 'message' => 'Invalid password'));
                    }
                } else {
                    // User not found
                    echo json_encode(array('status' => 'error', 'message' => 'User not found'));
                }

                $stmt->close();
                $conn->close();
            } else {
                // Invalid request
                echo json_encode(array('status' => 'error', 'message' => 'Invalid request'));
            }
        }

        // Handle signup action
        elseif ($action === 'signup') {
            if (isset($_POST['username']) && isset($_POST['email']) && isset($_POST['password'])) {
                $username = $_POST['username'];
                $email = $_POST['email'];
                $password = password_hash($_POST['password'], PASSWORD_DEFAULT); // Hash password for security

                $conn = connectDB();
                $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
                $stmt->bind_param("sss", $username, $email, $password);

                if ($stmt->execute()) {
                    // Signup successful
                    echo json_encode(array('status' => 'success', 'message' => 'Signup successful'));
                } else {
                    // Signup failed
                    echo json_encode(array('status' => 'error', 'message' => 'Signup failed'));
                }

                $stmt->close();
                $conn->close();
            } else {
                // Invalid request
                echo json_encode(array('status' => 'error', 'message' => 'Invalid request'));
            }
        }

        // Invalid action
        else {
            echo json_encode(array('status' => 'error', 'message' => 'Invalid action'));
        }
    } else {
        // No action provided
        echo json_encode(array('status' => 'error', 'message' => 'No action provided'));
    }
} else {
    // Invalid request method
    echo json_encode(array('status' => 'error', 'message' => 'Invalid request method'));
}
?>