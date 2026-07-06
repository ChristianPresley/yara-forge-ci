<?php
// Benign contact form handler - legitimate goodware sample.
// Reads POST input but never eval()s it; validates and emails safely.

$name  = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_SPECIAL_CHARS);
$email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
$body  = filter_input(INPUT_POST, 'message', FILTER_SANITIZE_SPECIAL_CHARS);

if ($email && $name) {
    mail('support@example.com', "Contact from $name", $body);
    echo "Thanks, we'll be in touch.";
} else {
    http_response_code(400);
    echo "Invalid input.";
}
?>
