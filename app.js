const express = require('express');
const exphbs = require('express-handlebars');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const db = require("./database.js")
const auth = require("./auth.js")
const app = express();
const authTokens = {};



// to support URL-encoded bodies
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cookieParser());

app.use((req, res, next) => {
    const authToken = req.cookies['AuthToken'];
    req.user = authTokens[authToken];
    next();
});

app.engine('hbs', exphbs({
    extname: '.hbs'
}));

app.set('view engine', 'hbs');

app.get('/', (req, res) => {
    res.render('home', {
        user: req.user
    });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    var sql = "SELECT * FROM user WHERE email = ?";
    db.all(sql, [email], (err, rows) => {
        if (err) {
            res.render('login', {
                message: 'Error: ' + err,
                messageClass: 'alert-danger'
            });
        } else {
            const user = rows[0]
            if(user){
                if (auth.isValidPass(password, user['password'])) {
                    const authToken = auth.generateAuthToken(user);
                    authTokens[authToken] = email;
                    res.cookie('AuthToken', authToken);
                    res.render('home', {
                        user: user
                    });
                    return;
                } else {
                    res.render('login', {
                        message: 'Invalid password',
                        messageClass: 'alert-danger'
                    });
                }
            } else {
                res.render('login', {
                    message: 'User does not exist',
                    messageClass: 'alert-danger'
                });
            }
        }
    });
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.get('/logout', (req, res) => {
    if (req.user) {
        res.cookie('AuthToken', '') // Quan fem logout el token es buida
        req.user = null
        res.render('home', {
            user: req.user
        });
    }
});

app.post('/register', (req, res) => {
    
    const { email, firstName, lastName, password, confirmPassword, adminCheck } = req.body; // adminCheck es un boolean

    if (password === confirmPassword) {
        const hashedPassword = auth.getHashedPassword(password);

        var sql ='INSERT INTO user (name, email, password, role) VALUES (?,?,?,?)'
        var params =[firstName + lastName, email, hashedPassword, adminCheck === "on" ? 'admin' : 'user'] // Al ser adminCheck boolean, si està a true és perque l'usuari serà admin, si no, es user
        db.run(sql, params, function (err) {
            if (err){ // Si la inserció dona error és perque l'usuari ja existeix
                console.log(err)
                res.render('register', {
                    message: 'User already registered.',
                    messageClass: 'alert-danger'
                });
                return;
            }
            res.render('login', {
                message: 'Registration Complete. Please login to continue.',
                messageClass: 'alert-success'
            });
            return;
        });
    } else {
        res.render('register', {
            message: 'Password does not match.',
            messageClass: 'alert-danger'
        });
    }
});

app.get('/admin', auth.authenticateJWT, auth.authorizeAdmin, (req, res) => { // Renderitzem admin passant per dos middlewares. El primer per a verificar el token i el segon per a verificar que l'usuari és admin
    res.render('admin');
});

app.get('/protected', auth.authenticateJWT, (req, res) => { // Al protected poden accedir tots els usuaris autenticats, per tant, sols comprovem que el token siga valid
    res.render('protected');
});


//app.listen(3000);
const port = process.env.PORT || 9999;
app.listen(port, () => {
    console.log('Biel Server listening at http://localhost:' + port);
});

//Respuesta ante consultas de rutas inexistentes

app.use(function (req, res) {
    res.status(404).json({ "error": "Invalid endpoint. V1"});
    
});