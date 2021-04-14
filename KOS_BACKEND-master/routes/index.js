var express = require('express');
var router = express.Router();
const exphbs = require('express-handlebars');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

// To support URL-encoded bodies
router.use(bodyParser.urlencoded({ extended: true }));

// To parse cookies from the HTTP Request
router.use(cookieParser());

router.use(cors({origin:true,credentials: true}));

router.use((req, res, next) => {
  // Get auth token from the cookies
  const authToken = req.cookies['AuthToken'];

  // Inject the user to the request
  req.user = authTokens[authToken];

  next();
});

//AUX
const getHashedPassword = (password) => {
  const sha256 = crypto.createHash('sha256');
  const hash = sha256.update(password).digest('base64');
  return hash;
}
const authTokens = {};

const generateAuthToken = () => {
  return crypto.randomBytes(30).toString('hex');
}
const users = [
  // This user is added to the array to avoid creating a new user on each restart
  {
    firstName: 'Kos',
    lastName: 'Advice',
    email: 'kos@kosadvice.es',
    // This is the SHA256 hash for value of `password`
    password: 'YNac2h83JtQBHZUmay9eXgW8TNucRPXCGjX/MWb6zD8='
  }
];

router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.get('/login', (req, res) => {
  res.render('login');
});

router.post('/signin', (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = getHashedPassword(password);

  const user = users.find(u => {
    return u.email === email && hashedPassword === u.password
  });

  if (user) {
    const authToken = generateAuthToken();

    // Store authentication token
    authTokens[authToken] = user;

    // Setting the auth token in cookies
    res.cookie('AuthToken', authToken);

    // Redirect user to the protected page
    res.redirect('/protected');
  } else {
    res.render('login', {
      message: 'Invalid username or password',
      messageClass: 'alert-danger'
    });
  }
});

router.post('/login', (req, res) => {
  console.log(req.body)
  const { email, password } = req.body.user;
  const hashedPassword = getHashedPassword(password);

  const user = users.find(u => {
    return u.email === email && hashedPassword === u.password
  });

  if (user) {
    const authToken = generateAuthToken();

    // Store authentication token
    authTokens[authToken] = user;

    // Setting the auth token in cookies
    res.cookie('AuthToken', authToken);

    // Redirect user to the protected page
    res.json({
      logged_in: true,
      user: user
    });
  } else {
    res.json({
      logged_in: false
    });
  }
});

router.get('/protected', (req, res) => {
  if (req.user) {
    res.render('protected');
  } else {
    res.render('login', {
      message: 'Please login to continue',
      messageClass: 'alert-danger'
    });
  }
});

router.get('/test', (req, res) => {
  const hashedPassword = getHashedPassword("kos");
  console.log(hashedPassword);
});

router.get('/downloadFile', (req, res, next) => {
  console.log("GET download file.");
  const excelFilePath = path.join(__dirname, '../files/CHARGING_INFO.xlsx');
  //res.attachment(excelFilePath);
  res.download(excelFilePath);
});

router.get('/getFile', (req, res) => {
  const excelFilePath = path.join(__dirname, '../files/CHARGING_INFO.xlsx');
  //const excelFilePath = path.join(__dirname, '../../../......./CHARGING_INFO.xlsx');
  fs.readFile(excelFilePath, function(err, data){
    if(err){
      res.statusCode = 500;
      res.end(`Error getting the file: ${err}.`);
    } else {
      res.setHeader('Content-type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' );
      //res.setHeader("Content-Type", "application/vnd.ms-excel");
      res.end(data);
    }
  });
});

router.post('/uploadFile', function(req, res) {

  if (!req.files || Object.keys(req.files).length === 0) {
    return res.status(400).send('No files were uploaded.');
  }
  console.log(req.files);
  let excelFile = req.files.excelFile;

  excelFile.mv('files/CHARGING_INFO.xlsx', function (err) {
  //excelFile.mv('../../../......../CHARGING_INFO.xlsx', function (err) {
    if (err)
      return res.status(500).send(err);

    res.send('File uploaded!');
  });
});

module.exports = router;

