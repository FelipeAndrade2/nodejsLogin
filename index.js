/*
RESTFul Services by NodeJS
Author: Felipe
ubdate:10/10/2018
*/

var crypto = require('crypto');
var uuid = require('uuid');
var express = require('express');
var mysql = require('mysql');
var bodyParser = require('body-parser');

//Connect to MySQL
var con = mysql.createConnection({
    host: 'localhost', //Replace your host IP
    user: 'root',
    password: 'pass',
    database: 'DemoNodeJs'
});

//PASSWORD ULTIL
var genRandomString = function (length) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex') /* convert to hexa format */
        .slice(0, length); /* return required number of characters */
};

var sha512 = function (password, salt) {
    var hash = crypto.createHmac('sha512', salt); //use SHA512
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt: salt,
        passwordHash: value
    };
};

function saltHashPassword(userPassword) {
    var salt = genRandomString(16); //Gen random string with 16 character to salt
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}

var app = express();
app.use(bodyParser.json());// Accept JSON Params
app.use(bodyParser.urlencoded({ extended: true })); //accept URL Encoded params

app.post('/register/', (req, res, next) => {
    // console.log(req.body);

    const postData = req.body;

    var uid = uuid.v4(); //Get UUID v4 like '110abacsasas-af0x-90333-casasjksk
    var plaint_password = postData.password; // Get password from post params
    var hash_data = saltHashPassword(plaint_password);
    var password = hash_data.passwordHash; //Get hash value
    var salt = hash_data.salt; // Get salt

    var name = postData.name;
    var email = postData.email;

    con.query('SELECT * FROM User where email = ?', [email], function (err, result) {
        if (!err) {
            console.log(result);
            if (result.length) {
                res.json({ success: false, message: 'User already exists!!!' });
            } else {
                con.query('INSERT INTO User(unique_id, name, email, encrypted_password, salt, created_at, updated_at) VALUES (?,?,?,?,?,NOW(),NOW())', 
                [uid, name, email, password, salt], function (err, result, fields) {
                    if (!err) {
                        res.json({ success: true, message: 'Register successful' });
                    } else {
                        res.json({ success: false, message: 'Error registering' });
                        console.log(err);
                    }
                });
            }
        } else {
            console.log(err);
        }
    });
});


// app.get("/", (req, res, next) => {
//     console.log('Password: 123456');
//     var encrypt = saltHashPassword("123456")
//     console.log('Encrypt: ' + encrypt.passwordHash);
//     console.log('Salt: ' + encrypt.salt);
// });

//Start Server
app.listen(3000, () => {
    console.log('Test Restful running on port 3000');
});
