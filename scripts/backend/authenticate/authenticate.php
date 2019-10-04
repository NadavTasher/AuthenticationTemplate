<?php
include_once "api.php";
authenticate();
echo json_encode($result);