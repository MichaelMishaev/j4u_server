  var fs = require('fs');
  const AWS = require('aws-sdk');
  var http = require('http');
  var https = require('https');
  const axios = require('axios');
  const TelegramBot = require('node-telegram-bot-api');
   //var privateKey  = fs.readFileSync('/usr/share/pki/ca-trust-source/j4r_co_il_private.key', 'utf8');
   //var certificate = fs.readFileSync('/usr/share/pki/ca-trust-source/j4r.co.il.crt', 'utf8');

  var express = require("express");
  var mysql = require('mysql');
  var bodyParser = require('body-parser');
  var app = express();
  var multer  = require('multer');
  var multerS3 = require('multer-s3')
  AWS.config.update({
    secretAccessKey: 'pFCgFDp1fmpAxka9onFcnfMMp77VG4Y2RdLe2CXQ',
    accessKeyId: 'AKIAI5J3W4DWTUKRDKVA',
    region: 'eu-central-1'
});
  var s3 = new AWS.S3({
    params: {
      Bucket: 'j4u-eu'
    }
  });

  var upload = multer({
    storage: multerS3({
      s3: s3,
      bucket: 'j4u-eu',
      metadata: function (req, file, cb) {
        cb(null, {fieldName: file.fieldname});
      },
      key: function (req, file, cb) {
        cb(null, file.originalname )
      }
    })
  })
  const log4js = require('log4js');
  const jwt = require('jsonwebtoken');
  const passport = require('passport');
  const passportJWT = require('passport-jwt');

  var xlsx = require('node-xlsx').default;

  var nodemailer = require('nodemailer');

 // var credentials = {key: privateKey, cert: certificate};

  // your express configuration here

  var httpServer = http.createServer(app);
  // var httpsServer = https.createServer(credentials, app);

  var jobsUpdateBotToken = '1025824180:AAF3NIo2jAD8ppaN2J64I9OmXPhp7Tci-3M'
  let socketIO = require('socket.io');
  let io = socketIO(httpServer);
  // httpsServer.listen(3000,function(){
  //   console.log("server is listen 3000")
  // });
  console.log("skip server listen")


  httpServer.listen(3001,function(){
    console.log("server is listen 3001")
  });


  let ExtractJwt = passportJWT.ExtractJwt;
  let JwtStrategy = passportJWT.Strategy;

  let jwtOptions = {};
  jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
  jwtOptions.secretOrKey = 'skqpcqfzar';

  // lets create our strategy for web token
  let strategy = new JwtStrategy(jwtOptions, function(jwt_payload, next) {
    let user = getUser({ id: 1 });//jwt_payload.id 

    if (user) {
      next(null, user);
    } else {
      next(null, false);
    }
  });
  // use the strategy
  passport.use(strategy);
  log4js.configure({
    appenders: { cheese: { type: 'file', filename: 'cheese.log' } },
    categories: { default: { appenders: ['cheese'], level: 'error' } }
  });
  
  const logger = log4js.getLogger('cheese');

  // var storage = multer.diskStorage({
  //     destination: function (req, file, cb) {
  //       cb(null, './tmp')
  //     },
  //     filename: function (req, file, cb) {
  //       cb(null, file.originalname + '.doc')
  //     }
  //   })

  //   var storageFromWeb = multer.diskStorage({
  //     destination: function (req, file, cb) {
  //       cb(null, './fromWeb')
  //     },
  //     filename: function (req, file, cb) {
  //       cb(null, file.originalname + '.doc')
  //     }
  //   })
  //   var storageExcel = multer.diskStorage({
  //     destination: function (req, file, cb) {
  //       cb(null, './jobsExcel')
  //     },
  //     filename: function (req, file, cb) {
  //       cb(null, file.originalname + '.xlsx')
  //     }
  //   })
  const Sequelize = require('sequelize');
  // var upload = multer({ storage: storage })
  // var uploadFromWeb = multer({ storage: storage })
  // var uploadExcel = multer({ storage: storageExcel })

  // initialze an instance of Sequelize

  const sequelize = new Sequelize({
    host:'localhost',
    database: 'myjobs',
    username: '345287',
    password: 'Jtbdtjtb6262',
    dialect: 'mysql',
  });


  var db_config = {
      host: "localhost",
      user: "345287",
      password: "Jtbdtjtb6262",
      database : 'myjobs',
      multipleStatements: true
  };

 // const bot = new TelegramBot(jobsUpdateBotToken, {polling: true});

  var con;

  function handleDisconnect() {
    con = mysql.createConnection(db_config); // Recreate the connection, since
                                                    // the old one cannot be reused.

    con.connect(function(err) {              // The server is either down
      if(err) {                                     // or restarting (takes a while sometimes).
        console.log('error when connecting to db:', err);
        setTimeout(handleDisconnect, 2000); // We introduce a delay before attempting to reconnect,
      }                                     // to avoid a hot loop, and to allow our node script to
    });                                     // process asynchronous requests in the meantime.
                                            // If you're also serving http, display a 503 error.
    con.on('error', function(err) {
      console.log('db error', err);
      if(err.code === 'PROTOCOL_CONNECTION_LOST') { // Connection to the MySQL server is usually
        handleDisconnect();                         // lost due to either server restart, or a
      } else {                                      // connnection idle timeout (the wait_timeout
        throw err;                                  // server variable configures this)
      }
    });
  }

  handleDisconnect();



  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({
      extended: true
  }));
  // initialize passport with express
  app.use(passport.initialize());

  // use it before all   definitions
  //app.use(cors({origin: 'http://localhost:4200'}));
  const sitecors = {
    origin: ['https://jobs4home.net','http://3.125.167.138','http://3.127.25.25',
      'https://www.jobs4home.net','https://j4u.works','https://www.j4u.works','http://localhost:4200'],
    defaul: 'https://jobs4home.net'
  }


  app.use(function (req, res, next) {
    console.log(req.header('host').toLowerCase());
      var origin = sitecors.origin.indexOf(req.header('host').toLowerCase()) > -1 ? req.headers.origin : sitecors.defaul;

      // Website you wish to allow to connect
      // res.setHeader('Access-Control-Allow-Origin', 'http://jobs4home.net');
      res.setHeader('Access-Control-Allow-Origin', '*');
      // Request methods you wish to allow
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

      // Request headers you wish to allow
      res.setHeader('Access-Control-Allow-Headers', 'Origin,X-Requested-With,content-type,Authorization');

      // Set to true if you need the website to include cookies in the requests sent
      // to the API (e.g. in case you use sessions)
      res.setHeader('Access-Control-Allow-Credentials', true);

      // Pass to next layer of middleware
      next();
  });

  // check the databse connection
  // sequelize
  //   .authenticate()
  //   .then(() => console.log('Connection has been established successfully.'))
  //   .catch(err => console.error('Unable to connect to the database:', err));

  // create user model
  const User = sequelize.define('user', {
    fullName: {
      type: Sequelize.STRING,
    },
    password: {
      type: Sequelize.STRING,
    },
    email:{
      type: Sequelize.STRING
    },
    phoneNumber:{
      type: Sequelize.STRING
    },
    isActive:{
      type: Sequelize.BOOLEAN
    },
    lastLoginDate:{
      type: Sequelize.DATE
    },
    isTrusted:{
      type: Sequelize.BOOLEAN
    },
    userType:{
      type: Sequelize.INTEGER
    }
  });
debugger;
  // create table with user model
  User.sync()
    .then(() => console.log('User table created successfully'))
    .catch(err => console.log('oooh, did you enter wrong database credentials?'));

  // create some helper functions to work on the database
  const createUser = async ({ fullName, password, email,isActive, phoneNumber }) => {
    return await User.create({ fullName, password, email,isActive,phoneNumber });
  };
  debugger;
  const getAllUsers = async () => {
    return await User.findAll();
  };

  const getUser = async obj => {
    return await User.findOne({
      where: obj,
    });
  };
  var transporter = nodemailer.createTransport({
      host: 'smtp.office365.com', // Office 365 server
          port: 587,     // secure SMTP
          secure: false, // false for TLS - as a boolean not string - but the default is false so just remove this completely
          auth: {
              user: "info@jobhome4u.com",
              pass: "Jtbdtjtb6262"
          },
          tls: {
              ciphers: 'SSLv3'
          }
    });
    
    var mailOptions = {
      from: 'info@j4u.work',
      to: 'info@j4u.work',
      subject: 'password reset request',
      text: 'That was easy!'
    };

    var onlineUsersArr = [];

  io.on('connection', (socket) => {
    socket.on('connectedUser', (users) =>{
      socket.name = users;
      if(onlineUsersArr.indexOf(users) === -1){
        onlineUsersArr.push(users);

      }
      io.emit('connectedUser', onlineUsersArr);
      
    });
    socket.on('disconnect', (data) => {
      onlineUsersArr = onlineUsersArr.filter(x=>x != socket.name);
      io.emit('disconnect', onlineUsersArr);
    });
    socket.on('new-message', (message) => {
      try{
        let m = JSON.parse(message);

        var sql = `INSERT INTO UserMessages  (FromUser,ToUser,Message)
                   Values (${m.FromUser},${m.ToUser},'${m.Message}')`;
        con.query(sql, function (err, result) {
          if (err) throw err;
          return io.emit('new-message', message);   
     
        });
      }
      catch (e) {
        console.log(e)
        throw e
      }
        
    });
  });

  // get all users
  app.get('/users',passport.authenticate('jwt', { session: false }), function(req, res) {
    getAllUsers().then(user => res.json(user));
  });

  app.get('/test', function(req, res) {
    res.json("ok");
  });

  app.get("/generalMessages",passport.authenticate('jwt', { session: false }), (req, res, next) => {
      
    var sql = `SELECT Message FROM generalmessages WHERE isactive = 1`;
    con.query(sql, function (err, result) {
        if (err) throw err;
        res.json(result);
    });

  });

  app.get("/jobs", passport.authenticate('jwt', { session: false }),(req, res, next) => {
      
      var sql = `SELECT * FROM job WHERE Status = 1 ORDER BY IsImportant desc, Company = 'HR' DESC,date_created DESC`;
      con.query(sql, function (err, result) {
          if (err) throw err;
          result.forEach(element => {
              element.Description = unescape(element.Description)
              //element.Commission = Math.floor(element.Commission * 0.6)
          });
        

          res.json(result);
      });
  });
  app.get("/jobsBase",(req, res, next) => {
      
    var sql = `SELECT ID, Title,Date,Questions,Description,AgentDescription,Categories,Commission FROM job WHERE Status = 1 ORDER BY IsImportant desc, Company = 'HR' DESC,date_created DESC`;
    con.query(sql, function (err, result) {
        if (err) throw err;
        result.forEach(element => {
            element.Description = unescape(element.Description)
            //element.Commission = Math.floor(element.Commission * 0.6)
        });
      

        res.json(result);
    });
});
  app.get("/closedJobs", passport.authenticate('jwt', { session: false }),(req, res, next) => {
      
    var sql = `SELECT * FROM job where Status = 0 and Company != 'SVT' ORDER BY IsImportant, Company = 'HR' desc`;
    con.query(sql, function (err, result) {
        if (err) throw err;
        result.forEach(element => {
            element.Description = unescape(element.Description)
            //element.Commission = Math.floor(element.Commission * 0.6)
        });
      

        res.json(result);
    });
});

  app.get("/jobCandidateByUser",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    //removed the 0.6
      var sql = `SELECT JobId,jc.Id as JobCandidateId,jc.Status,j.Title,Concat(c.FirstName,' ', c.LastName) as CandidateName, CAST(IsInternalReject AS UNSIGNED) AS IsInternalReject,StatusDescription, (j.Commission ) as Commission, j.Questions,jc.QuestionsAndAnswers, jc.updated_at
      FROM jobcandidate jc 
      INNER JOIN candidate c ON jc.CandidateId = c.Id
      INNER JOIN job j ON jc.JobId = j.Id  
      WHERE jc.IsDeleted = 0 and c.userid=` + req.query.u + ` ORDER BY jc.Id DESC`;
      con.query(sql, function (err, result) {
          if (err) throw err;
          res.json(result);
      });
  });
  app.get("/bonusesByUser",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var sql = `SELECT *
    FROM UserBonuses WHERE userid=` + req.query.u;
    con.query(sql, function (err, result) {
        if (err) throw err;
        res.json(result);
    });
});
  app.get("/subordinateCandidateByUser",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    
    if (req.headers && req.headers.authorization) {
      var authorization = req.headers.authorization.split(' ')[1],
          decoded;
      try {
          decoded = jwt.verify(authorization, jwtOptions.secretOrKey);
          //removed the commission
          var sql = `SELECT u.id,u.fullName AS userName, JobId,jc.Id as JobCandidateId,jc.Status,j.Title,Concat(c.FirstName,' ', c.LastName) as CandidateName, CAST(IsInternalReject AS UNSIGNED) AS IsInternalReject,StatusDescription, (j.Commission ) as Commission, j.Questions,jc.QuestionsAndAnswers
          FROM jobcandidate jc
          INNER JOIN candidate c ON jc.CandidateId = c.Id 
          INNER JOIN users u ON jc.UserId = u.id
          INNER JOIN job j ON jc.JobId = j.Id
          WHERE jc.IsDeleted = 0 and jc.UserId IN (SELECT id FROM users WHERE addedby = ${ decoded.id})`;
          con.query(sql, function (err, result) {
              if (err) throw err;
              res.json(result);
          });
      } catch (e) {
          return res.status(401).send('unauthorized');
      }
    }
    
  
  });

  app.get("/candidateJobsByUser",passport.authenticate('jwt', { session: false }), (req, res, next) => {
      var sql = `SELECT jc.Id, jc.JobId, j.Title,jc.Status, jc.StatusDescription,j.Questions, jc.QuestionsAndAnswers FROM jobcandidate jc
                  LEFT JOIN job j ON jc.JobId = j.ID
                  WHERE jc.IsDeleted = 0 AND jc.CandidateId = ` + parseInt(req.query.CandidateId) + ` AND jc.UserId = ` + parseInt(req.query.u);
      con.query(sql, function (err, result) {
          if (err) throw err;
          res.json(result);
      });
  });
  app.get("/userRanking", passport.authenticate('jwt', { session: false }), (req, res, next) => {
    //removed the 0.6 commission
    var sql = `SELECT COUNT(jc.UserId) AS candidatesForUser,jc.UserId, Sum(j.Commission ) AS Commission
     FROM jobcandidate jc inner JOIN job j on jc.JobId = j.Id
     WHERE jc.IsDeleted = 0
                GROUP BY UserId
                ORDER BY Commission desc`;
    con.query(sql, function (err, result) {
        if (err) throw err;
        res.json(result);
    });
  });
  app.get("/userProfits", passport.authenticate('jwt', { session: false }), (req, res, next) => {
      var sql = `SELECT * FROM UserProfits WHERE UserId=` + req.query.id;
      con.query(sql, function (err, result) {
          if (err) throw err;
          res.json(result);
      });
  });
  app.post("/jobCandidate",passport.authenticate('jwt', { session: false }), (req, res, next) => {
     return addJobCandidate(req,res,next)
  });

  app.post("/ExternalJobCandidate", (req, res, next) => {
    return addJobCandidate(req,res,next)
 });
  addJobCandidate = (req, res, next) =>{
    var d = req.body;
    var sql = `INSERT INTO JobCandidate  (CreateDate,JobId,CandidateId,QuestionsAndAnswers,IsSent,UserId,Status,JobName) Values(?,?,?,?,?,?,?,?)`;
    var userData = [new Date(),d.JobId,d.CandidateId,JSON.stringify(d.QuestionsAndAnswers),0, d.UserId, 'New', d.JobName];
    con.query(sql,userData, function (err, result) {
        if (err){
            return res.status(500).json(err);
        } else{
            //bot.sendMessage(-206212060, `סוכן ${d.UserId} הגיש למשרה ${d.JobId} את מועמד ${d.CandidateId}`);
        
            return res.json(result);

        }
    });
  }
  app.post("/generalMessages",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var message = req.body.message;
    var sql = `INSERT INTO generalmessages (Message,IsActive) values(${mysql.escape(message)},1)`;
    con.query(sql, function (err, result) {
        if (err) throw err;
        res.json(result);
    });

  });
  app.post("/job",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var d = req.body;
    if (req.headers && req.headers.authorization) {
      var authorization = req.headers.authorization.split(' ')[1],
          
          decoded = jwt.verify(authorization, jwtOptions.secretOrKey);
      
    var sql = `INSERT INTO Job
      (ID,Title,Commission,Company,Description,CompanyDescription,Date,JobType,Locations,Questions,Categories,UserId,AgentDescription, Period,PaymentPeriod, Areas,SubCategory, Status,IsImportant)
       Values(${d.Id},${mysql.escape(d.Title)},${d.Commission},'HR',${mysql.escape(d.Description)},
       ${mysql.escape(d.CompanyDescription)},'${new Date().toDateString()}','${d.JobType}',${mysql.escape(d.Locations)},${mysql.escape(d.Questions)},'${d.Categories}',${d.UserId}, ${mysql.escape(d.AgentDescription)},'${d.Period}','${d.PaymentPeriod}','${d.Areas}','${d.SubCategory}', ${d.Status},${d.IsImportant})
       ON DUPLICATE KEY UPDATE Title=VALUES(Title), Commission=VALUES(Commission), CompanyDescription=VALUES(CompanyDescription),UserId=VALUES(UserId),
       Date=VALUES(Date),Description=VALUES(Description), JobType=VALUES(JobType), Locations=VALUES(Locations),Period=VALUES(Period),Questions=VALUES(Questions),Areas=VALUES(Areas),Categories=VALUES(Categories),SubCategory=VALUES(SubCategory),AgentDescription=VALUES(AgentDescription),Status=VALUES(Status),IsImportant=VALUES(IsImportant)`;
   
    con.query(sql, function (err, result) {
        if (err){
            return res.status(500).json(err.code);
        } else{
            //result.insertId
            var updateExternalIdsSql = `UPDATE job set ExternalJobId = ${result.insertId} WHERE Id = ${result.insertId}`
            con.query(updateExternalIdsSql, function (err, result) {
              return res.json({});
            });

        }
    });
  }
  });

  app.post("/deleteJobCandidate",passport.authenticate('jwt',{session:false}),(req, res) =>{
    if (req.headers && req.headers.authorization) {
      var authorization = req.headers.authorization.split(' ')[1],
          decoded;
      try {
          decoded = jwt.verify(authorization, jwtOptions.secretOrKey);
      } catch (e) {
          return res.status(401).send('unauthorized');
      }
      var sql = `UPDATE JobCandidate SET IsDeleted = 1 WHERE Id = ${req.body.id} and UserId = ${decoded.id}`
      con.query(sql, function (err, result) {
        if (err){
            return res.status(500).json(err.code);
        } else{
            return res.json(result);

        }
    });
  }

  })
  app.put("/jobCandidate",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var d = req.body;
    var sql = `UPDATE JobCandidate SET QuestionsAndAnswers = '${d.QuestionsAndAnswers}' , IsUpdatedByUser=1, IsInternalReject = 2 where Id=${d.Id}`;
    con.query(sql, function (err, result) {
        if (err){
            return res.status(500).json(err.code);
        } else{
            return res.json(result);

        }
    });
  });
  app.put("/CandidateIsFromPool",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var d = req.body;
    var sql = `UPDATE Candidate SET IsFromPool = '${d.isFromPool}' where Id=${d.candidateId}`;
    con.query(sql, function (err, result) {
        if (err){
            return res.status(500).json(err.code);
        } else{
            return res.json(result);

        }
    });
  });
  //todo fix statuses
  app.put("/jobCandidateStatus",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var d = req.body;
    var status =  d.Status.description || d.Status;
    var isInternalReject = status == 'lack of details' || d.Status.id == 3 ? 1 : 0;
    console.log('status ' + status + ' is internal reject ' + isInternalReject)
    var isAddBonus = status == 'Resume sent'
    var historySql = `INSERT INTO JobCandidateHistory (JobCandidateId,Status,StatusDescription,InternalRemarks)
                     Values('${d.jobCandidateId}','${status}','${d.StatusDescription || ''}','${d.InternalRemarks || ''}')`;
    var sql = `UPDATE JobCandidate SET Status = '${status}' , IsInternalReject = ${isInternalReject},
               StatusDescription='${d.StatusDescription}', InternalRemarks='${d.InternalRemarks}'
               where Id=${d.jobCandidateId}`;

    //sendMessageToBot(status,d)
    if(isAddBonus){
      var bonusSql = `INSERT INTO UserBonuses (UserId,JobCandidateId,BonusAmount,BonusType) VALUES 
                      (${d.UserId},${d.jobCandidateId},2,1)
          ON DUPLICATE KEY UPDATE UserId=VALUES(UserId), JobCandidateId=VALUES(JobCandidateId), BonusAmount=VALUES(BonusAmount), BonusType=VALUES(BonusType)`
      con.query(bonusSql, function (err, result) {

      })
    }
    //syncCandidateFromPool(d.CandidateId, status)
    con.query(sql, function (err, result) {
        if (err){
            return res.status(500).json(err.code);
        } else{
          con.query(historySql, function (err, result) {
            if(d.startWorkDate){
              //todo
              var workDateSql = `INSERT INTO CandidateWorkActivity (JobCandidateId,StartWorkDate) VALUES (${d.jobCandidateId},'${d.startWorkDate}')
                                ON DUPLICATE KEY UPDATE StartWorkDate='${d.startWorkDate}'`;
              con.query(workDateSql, function (err, result) {
                if (err){
                  return res.status(500).json(workDateSql);
                }
                return res.json(result);

              });

            } else{
              return res.json(result);

            }
          });


        }
    });
  });
  app.put("/JobCandidateHistory",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var d = req.body;
    var historySql = `INSERT INTO JobCandidateHistory (JobCandidateId,Status,StatusDescription)
                     Values('${d.jobCandidateId}','Update from agent','${d.StatusDescription}')`;

    //always updates to InternalReject = 2 to send it to the coordinator
    var jobCandidateSql = `UPDATE JobCandidate Set IsInternalReject = 2,IsCoordinatorRead = 0 where Id = '${d.jobCandidateId}'`;             


     con.query(historySql, function (err, result) {
      if (err){
            return res.status(500).json(err.code);
          } 
          con.query(jobCandidateSql, function (err, result) {
            return res.json(result);
          });
         
        });
  });

  
  app.put("/jobCandidateIsRead",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var d = req.body;
    var sql = `UPDATE JobCandidate SET IsRead = 1,isCoordinatorRead = 1
               where Id=${d.jobCandidateId}`;
    con.query(sql, function (err, result) {
        if (err){
            return res.status(500).json(err.code);
        } else{
            return res.json(result);

        }
    });
  });
  app.put("/jobCandidateIsCoordinatorRead",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var d = req.body;
    var sql = `UPDATE JobCandidate SET IsCoordinatorRead = 1
               where Id=${d.jobCandidateId}`;
    con.query(sql, function (err, result) {
        if (err){
            return res.status(500).json(err.code);
        } else{
            return res.json(result);

        }
    });
  });
  app.put("/jobUserId",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var d = req.body;
    var sql = `UPDATE Job SET UserId = ${d.userId}
               where Id=${d.jobId}`;
    con.query(sql, function (err, result) {
        if (err){
            return res.status(500).json(err.code);
        } else{
            return res.json({});

        }
    });
  });
  app.get("/candidates",passport.authenticate('jwt', { session: false }), (req, res, next) => {
      var sql = `SELECT * FROM  Candidate WHERE UserId = ` + req.query.u + ` ORDER BY Id DESC`;
      con.query(sql,async function (err, result) {
          if (err) throw err;

          let user = await getUser({ id: req.query.u });
          user.update(
            { lastLoginDate: new Date() },
            { where: { id: user.id } }).then(()=>{
            });
            
          res.json(result);
      });
  });
  app.get("/usersBase",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var sql = `SELECT Id,FullName,Email FROM  Users WHERE IsActive = 1 and UserType = 1`;
    con.query(sql,async function (err, result) {
        if (err) throw err;
        res.json(result);
    });
});
  app.get("/poolCandidates",passport.authenticate('jwt', { session: false }), (req, res, next) => {

    if (req.headers && req.headers.authorization) {
      var authorization = req.headers.authorization.split(' ')[1],
          decoded;
      try {
        decoded = jwt.verify(authorization, jwtOptions.secretOrKey);
        const userId = decoded.id;
        var sql = `SELECT c.Id as CandidateId,c.OriginalUserId,c.OriginalCandidateId, Concat(c.FirstName,' ', c.LastName) AS CandidateName, c.City,c.Email,c.PhoneNumber
                  , pcsc.SubCategoryId,ca.Name Categories, cit.Name Locations, a.Name Areas
                  FROM  Candidate c 
                  INNER JOIN PoolCandidateSubCategories pcsc on c.Id = pcsc.CandidateId
                  INNER JOIN SubCategories ca on pcsc.SubCategoryId = ca.Id
                  INNER JOIN poolcandidatescities pcc on c.Id = pcc.CandidateId
                  INNER JOIN Cities cit on pcc.CityId = cit.Id
                  INNER JOIN Areas a on cit.AreaId = a.Id
                  WHERE c.IsFromPool = 1 
                  AND NOT EXISTS( SELECT 1 FROM candidate c2 WHERE userid = ${userId} AND c2.PhoneNumber = c.PhoneNumber)`;
          con.query(sql,async function (err, result) {
            if (err) throw err;
            res.json(result);
          });
      }
      catch(e){
        return res.status(500).send(e);
      }
    } else{
      return res.status(401).send('unauthorized');

    }

});

app.get("/isPremittedToPool",passport.authenticate('jwt', { session: false }), (req, res, next) => {
  if (req.headers && req.headers.authorization) {
    var authorization = req.headers.authorization.split(' ')[1],
        decoded;
    try {
      decoded = jwt.verify(authorization, jwtOptions.secretOrKey);
      var d = new Date();
      monthAgo = d.setMonth(d.getMonth() - 1);
      // var sql = `SELECT 1 from users u
      //            where u.Id = ${decoded.id} AND
      //            u.LastLoginDate > (select from_unixtime(${monthAgo} / 1000) )
      //            AND (SELECT COUNT(*) 
      //            FROM UserBonuses WHERE UserId = ${decoded.id} and IsPaid = 0) > 5`
      var sql = `SELECT 1 from users u
                 where u.Id = ${decoded.id} AND IsPoolAllowed = 1`
     con.query(sql,async function (err, result) {
          if (err) throw err;
          res.json(result);
      });
    }
    catch(err){
      return res.status(401).send('unauthorized');
    }
  }
});
app.post("/ExternalCandidate", (req, res, next) => {
  return addCandidate(req, res, next,true);
});
app.post("/candidate",passport.authenticate('jwt', { session: false }), (req, res, next) => {
  return addCandidate(req, res, next);
});

  addCandidate = (req, res, next, updateOnDuplicate = false) =>{
    try{
      var user = req.body;
      var isPool = req.query.p == 'true' ? 1 : 0;
      var sql = `INSERT INTO Candidate (FirstName,LastName,City,Email,PhoneNumber,UserId,HasCV,internalComments,IsFromPool) Values(?,?,?,?,?,?,?,?,?)`;
      if(updateOnDuplicate){
        sql += ` ON DUPLICATE KEY UPDATE FirstName=VALUES(FirstName), City=VALUES(City),
                 Email=VALUES(Email), PhoneNumber=VALUES(PhoneNumber), UserId=VALUES(UserId), HasCV=VALUES(HasCV), internalComments=VALUES(internalComments),
                 IsFromPool=VALUES(IsFromPool)`
      }
      var userData = [user.FirstName,user.LastName,user.City,user.Email,user.PhoneNumber, req.query.u, user.HasCV || 0,user.InternalComments || '',isPool ];
      con.query(sql,userData, function (err, result) {
          if (err){
            res.json(err);
            throw err;
          } 
            
          res.json(result);
          
      });
    }
    catch(err){
      res.json(err);

    }
  }

  app.post("/poolCandidateToUser",passport.authenticate('jwt', { session: false }), (req, res, next) => {
      try{
        if (req.headers && req.headers.authorization) {
          var authorization = req.headers.authorization.split(' ')[1],
              decoded;
         // try {
            decoded = jwt.verify(authorization, jwtOptions.secretOrKey);
            var user = req.body;
            var candidateId = req.body.candidateId;
            var originalUserId = req.body.originalUserId || null;
            var originalCandidateId = req.body.originalCandidateId || null;
            var sql = `INSERT INTO candidate(FirstName,LastName,City,Email,PhoneNumber,Summary,HasCV,UserId,FakeEmail,InternalComments,UserRemark,IsFromPool,OriginalUserId,OriginalCandidateId)
            SELECT FirstName,LastName,City,Email,PhoneNumber,Summary,HasCV,${decoded.id},FakeEmail,InternalComments,UserRemark,0,${originalUserId }, ${originalCandidateId}
            FROM Candidate
            WHERE Id = ${candidateId}`;
            var userData = [user.FirstName,user.LastName,user.City,user.Email,user.PhoneNumber, req.query.u];
            con.query(sql,userData, function (err, result) {
                if (err) throw err;
                res.json(result);
            });
          // } catch (e) {
          //   return res.status(401).send(e);
          // }
        }
      }
      catch (e) {
        return res.status(500).send(e);
    }
    
  });
  app.post("/notifications",passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var d = req.body
    var sql = `INSERT INTO notifications  (UserId,Message,IsRead) Values (${d.userId},'${d.message}', 0)`;
    con.query(sql, function (err, result) {
      if (err) throw err;
      res.json({});       
    });
  })
  app.put("/candidate",passport.authenticate('jwt', { session: false }), (req, res, next) => {
      var user = req.body;
      var sql = `UPDATE Candidate SET FirstName = ` +mysql.escape(user.FirstName)+ `, LastName = `+ mysql.escape(user.LastName)+`, City = `+mysql.escape(user.City)+`
                , Email= '`+user.Email+`',PhoneNumber = '`+user.PhoneNumber+`', FileExtension='`+user.FileExtension+`',UserRemark = '`+ user.UserRemark+`', HasCV = `+user.HasCV+`
      WHERE ID = `+user.Id+``;

      con.query(sql, function (err, result) {
          if (err){
            throw err
          };
          res.json(result);
      });
  });
  app.put("/CandidateFileExtension", (req, res, next) => {
      var user = req.body;
      var sql = `UPDATE Candidate SET FileExtension='`+user.fileExension+`'
                WHERE ID = `+user.candidateId+``;
      con.query(sql, function (err, result) {
          if (err) throw err;
          res.json(result);
      });
  });
 

  app.post('/api/upload', upload.single('uploads'), (req, res) => {
  
      res.json({
          'message': 'File uploaded successfully'
      });
  });

  app.get('/download',passport.authenticate('jwt', { session: false }), function(req, res){
      
    const getParams = {
      Bucket: 'j4u-eu',
      Key: req.query.fileName
    };
    
    s3.getObject(getParams, function(err, data) {
      if (err){
        return res.status(400).send({success:false,err:err});
      }
      else{
        return res.send(data.Body);
      }
    });
    
    // var id = req.query.id;
    //   const file = `${__dirname}/tmp/${id}.doc`;
    //   res.sendFile(file); // Set disposition and send it.
  });
    
  app.get("/coordinatorsTable", passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var onlyHr =  req.query.onlyHr;

    if (req.headers && req.headers.authorization) {
      var authorization = req.headers.authorization.split(' ')[1],
          decoded;
      try {
        decoded = jwt.verify(authorization, jwtOptions.secretOrKey);
        var sql = `SELECT jc.Id as jobCandidateId,j.Id as JobId,j.Questions,jc.QuestionsAndAnswers,jc.IsRead,jc.IsCoordinatorRead, j.Title,j.ExternalJobId,c.HasCV,c.Id as CandidateId,jc.IsInternalReject,j.Description,
                  j.UserId as JobUserId,j.CompanyDescription,u.Id as UserId,u.fullName, u.email, u.phoneNumber,jc.Status,jc.StatusDescription,jc.InternalRemarks, c.FirstName,c.LastName,c.Email as CandidateEmail,c.PhoneNumber CandidatePhoneNumber,
                  jc.updated_at,c.OriginalCandidateId,c.FileExtension, IF(EXISTS (SELECT 1 FROM jobCandidate jc2 INNER JOIN candidate c2 ON jc2.CandidateId = c2.Id  WHERE c2.PhoneNumber = c.PhoneNumber AND jc2.Id != jc.Id),1,0) IsKnown
                  FROM job j
                  LEFT JOIN jobcandidate jc ON j.ID = jc.JobId 
                  LEFT JOIN users u ON jc.UserId = u.Id
                  LEFT JOIN candidate c ON jc.CandidateId = c.ID
                  WHERE (j.UserId = ${decoded.id} or ${decoded.userType} = 3)`;
          if(onlyHr){
            sql += ` and j.Company = 'HR'`
          }
          con.query(sql, function (err, result) {
            if (err) throw err;
            res.json(result);
          });
      }
      catch (e) {
        return res.status(401).send('unauthorized');
      }
    }
  });

  app.get("/coordinatorsSummary", passport.authenticate('jwt', { session: false }), (req, res, next) => {

    if (req.headers && req.headers.authorization) {
      var authorization = req.headers.authorization.split(' ')[1],
          decoded;
      try {
        decoded = jwt.verify(authorization, jwtOptions.secretOrKey);
        var sql = `SELECT jc.Id as jobCandidateId,j.Id as JobId,jc.IsRead, j.UserId
                  FROM job j
                  LEFT JOIN jobcandidate jc ON j.ID = jc.JobId 
                  WHERE j.UserId IS NOT NULL and j.Company = 'HR'`;
          con.query(sql, function (err, result) {
            if (err) throw err;
            res.json(result);
          });
      }
      catch (e) {
        return res.status(401).send('unauthorized');
      }
    }
  });
    
  app.get("/jobCandidateHistory", passport.authenticate('jwt', { session: false }), (req, res, next) => {

    var jobCandidateId = req.query.jobCandidateId;

    var sql = `SELECT *
              FROM jobcandidatehistory j
              WHERE j.jobCandidateId = ${jobCandidateId}`;
      con.query(sql, function (err, result) {
        if (err) throw err;
        res.json(result);
      });
  });

  app.get("/jobCandidateHistoryByUser", passport.authenticate('jwt', { session: false }), (req, res, next) => {

    if (req.headers && req.headers.authorization) {
      
      try {
        var authorization = req.headers.authorization.split(' ')[1];
        decoded = jwt.verify(authorization, jwtOptions.secretOrKey);

        var sql = `SELECT j.Status,j.CreatedAt,j.StatusDescription,j.InternalRemarks, jc.JobName, Concat(c.FirstName,' ', c.LastName) AS CandidateName
                  FROM jobcandidatehistory j
                  inner join jobCandidate jc
                  on j.jobCandidateId = jc.Id
                  inner join Candidate c
                  on jc.CandidateId = c.Id
                  WHERE jc.UserId = ${decoded.id} and 
                  j.Status != 'Update from agent'`;
                  con.query(sql, function (err, result) {
                    if (err) throw err;
                    res.json(result);
                  });
      }
      catch (e) {
        return res.status(401).send('unauthorized');
      }
    }
  });
  app.get("/notifications", passport.authenticate('jwt', { session: false }), (req, res, next) => {

    if (req.headers && req.headers.authorization) {
      
      try {
        var authorization = req.headers.authorization.split(' ')[1];
        decoded = jwt.verify(authorization, jwtOptions.secretOrKey);

        var sql = `SELECT *
                  FROM notifications n
                  WHERE n.UserId = ${decoded.id}`;
                  con.query(sql, function (err, result) {
                    if (err) throw err;
                    res.json(result);
                  });
      }
      catch (e) {
        return res.status(401).send('unauthorized');
      }
    }
  });
  app.get("/jobCandidateCompletedHistory", passport.authenticate('jwt', { session: false }), (req, res, next) => {

    if (req.headers && req.headers.authorization) {
      
      try {
        var authorization = req.headers.authorization.split(' ')[1];
        decoded = jwt.verify(authorization, jwtOptions.secretOrKey);

        var sql = `SELECT jch.*,jc.JobId, Concat(c.FirstName,' ', c.LastName) candidateName, c.Email candidateEmail, c.PhoneNumber candidatePhone
        , u.Email,u.PhoneNumber, u.fullName, cwa.StartWorkDate, cwa.EndWorkDate
        FROM jobcandidatehistory jch 
        INNER JOIN jobcandidate jc ON jch.JobCandidateId = jc.Id
        INNER JOIN candidate c ON jc.CandidateId = c.Id
        INNER JOIN users u ON c.UserId = u.Id
        LEFT JOIN candidateworkactivity cwa ON cwa.JobCandidateId = jc.Id
        where jch.Status = 'Accepted' OR jch.Status = 'Finished Working'
        ORDER BY CreatedAt desc        
        `;
        con.query(sql, function (err, result) {
          if (err) throw err;
          res.json(result);
        });
      }
      catch (e) {
        return res.status(401).send('unauthorized');
      }
    }
  });

  app.get("/lookups", (req, res, next) => {
    //todo improve to forkjoin
    var data = {}
    var sql = `SELECT * FROM Categories;SELECT * FROM Cities;SELECT * FROM Areas;SELECT * FROM SubCategories;SELECT * FROM JobStatus;SELECT * FROM JobType`;
      con.query(sql, function (err, result) {
        if (err) throw err;
        data.categories = result[0];
        data.cities = result[1];
        data.areas = result[2];
        data.subCategories = result[3];
        data.jobStatus = result[4];
        data.jobTypes = result[5];
        res.json(data);

      });
  });
  app.get("/report", passport.authenticate('jwt', { session: false }), (req, res, next) => {
    var sql = `SELECT j.id AS JobId,
    j.companyDescription AS Company_name,
    j.title AS Title,
    jc.Id AS JobCandidateId,
    jc.CreateDate Status_Date,
    jc.InternalRemarks,
    js.Name AS Status_Name,
    Concat(c.FirstName,' ', c.LastName) AS Candidate_Name, 
    c.PhoneNumber AS Candidate_PhoneNumber,
    c.Email AS Candidate_Email,
    u.fullName AS Agent_Name,
    u.email AS Agent_Email,
    u.phoneNumber AS Agent_PhoneNumber,
    um.fullName AS Recrutment_AgentName,
    jc.IsInternalReject,
    j.Status
FROM jobcandidate jc
INNER JOIN jobstatus js
   ON js.Name = jc.status
INNER JOIN job j
   ON jc.jobid= j.id
LEFT JOIN (select  JobCandidateId, max(createdAt)AS createdAt
from jobcandidatehistory jch
GROUP BY JobCandidateId
ORDER BY createdAt) AS jch
   ON jch.JobCandidateId = jc.id        
INNER JOIN candidate c
   ON c.id = jc.CandidateId
INNER JOIN users u
   ON u.id = jc.UserId         
INNER JOIN Users um        
   ON um.id = j.UserId 
WHERE js.id IN(1,3,4,5,12,13,14)        
AND j.company='hr' and jc.IsDeleted = 0`;
      con.query(sql, function (err, result) {
        if (err) throw err;
        res.json(result);

      });
  });

  app.get("/knownCandidateHistory",passport.authenticate('jwt', { session: false }), (req, res, next) =>{
    
    var sql = `SELECT jch.Status,jch.StatusDescription,jch.InternalRemarks,
                      u.fullname AS AgentFullName,jc.CreateDate CreateDate,
                      CONCAT(c.FirstName, ' ', c.LastName) AS CandidateName,
                      j.id AS JobID ,j.Title AS jobTitle
                      FROM jobcandidate jc
                      INNER JOIN jobcandidatehistory jch
                      ON jch.JobCandidateId = jc.Id
                      INNER JOIN job j ON j.id = jc.JobId
                      INNER JOIN USERs u ON u.id = jc.UserId
                      INNER JOIN candidate c ON c.id = jc.CandidateId
                      where c.Id = ${req.query.CandidateId}`
        con.query(sql, function (err, result) {
          if (err) throw err;
          res.json(result);
        });

  });

  app.get("/userManagers", passport.authenticate('jwt', { session: false }), (req, res, next) => {

    var sql = `SELECT u.fullName,u.id, um.ManagerId FROM UserManagers um INNER JOIN Users u on um.UserId = u.Id where um.UserType > 1`;
      con.query(sql, function (err, result) {
        if (err) throw err;
        res.json(result);       
      });
  });
  app.get("/userMessages", passport.authenticate('jwt', { session: false }), (req, res, next) => {

    if (req.headers && req.headers.authorization) {
      var authorization = req.headers.authorization.split(' ')[1],
          decoded;
      try {
        decoded = jwt.verify(authorization, jwtOptions.secretOrKey);
        var sql = `SELECT * FROM userMessages`;
        con.query(sql, function (err, result) {
          if (err) throw err;
          res.json(result);       
        });
      }
      catch(e){
        return res.status(401).send('unauthorized');
      }
    }
  });

  app.post("/userMessage", passport.authenticate('jwt', { session: false }), (req, res, next) => {

    if (req.headers && req.headers.authorization) {
      var authorization = req.headers.authorization.split(' ')[1],
          decoded;
      try {
        var d = req.body;
        decoded = jwt.verify(authorization, jwtOptions.secretOrKey);
        var sql = `INSERT INTO UserMessages  (FromUser,ToUser,Message) Values (${decoded.id},${d.ToUser},'${d.Message}')`;
        con.query(sql, function (err, result) {
          if (err) throw err;
          res.json({});       
        });
      }
      catch(e){
        return res.status(401).send('unauthorized');

      }
    }
  });

    ///Auth

    
  app.post("/auth/sign-in", async function(req, res, next) {
      const { email, password } = req.body;
      console.log("1111")
      if (email && password) {
        let user = await getUser({ email: email });
        if (!user) {
          res.status(401).json({ message: 'No such user found' });
        }
        if(!user.isActive){
          res.status(401).json({ message: 'User is not active' });

        } else if (user.password === password) {
          // from now on we'll identify the user by the id and the id is the 
          // only personalized value that goes into our token
          let payload = { id: user.id,name: user.fullName, updatedAt:new Date(),isTrusted: user.isTrusted, userType:user.userType  };
          let token = jwt.sign(payload, jwtOptions.secretOrKey);
          user.update(
            { lastLoginDate: new Date() },
            { where: { id: user.id } }).then(()=>{
              res.json({ msg: 'ok', token: token });
            });
        
        } else {
          res.status(401).json({ msg: 'Password is incorrect' });
        }
      }
  });
  app.post("/auth/sign-out", async function(req, res, next) {
    res.json({ msg: 'ok'});
  });
  app.post("/auth/sign-in-google", async function(req, res, next) {

    const token = req.body.token;
    const email = req.body.email;
    axios.get('https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=' + token)
    .then(async response => {
      let user = await getUser({ email: email });
      if(!user.isActive){
        res.status(401).json({ message: 'User is not active' });

      } 
      let payload = { id: user.id,name: user.fullName, updatedAt:new Date(),isTrusted: user.isTrusted, userType:user.userType  };
      let token = jwt.sign(payload, jwtOptions.secretOrKey);
      user.update(
        { lastLoginDate: new Date() },
        { where: { id: user.id } }).then(()=>{
          res.json({ msg: 'ok', token: token });
        });
     
    })
    .catch(error => {
      res.status(404).json({ message: error.message || error });
    });  
});

  app.post("/auth/sign-up", async (req, res, next) => {
      const { fullName, password, email, phoneNumber } = req.body;
      const isActive = true;
      let user = await getUser({ email: email });
      if(user){
        res.status(401).json({ msg: 'Duplicate email' });
        return;
      }
    createUser({ fullName, password, email, isActive, phoneNumber }).then(user =>{
      // var options = {
      //   from: 'info@jobhome4u.com',
      //   to: 'yacovbarboi@gmail.com', //email
      //   subject: 'אישור רישום J4U',
      //   text: `<div style="overflow: hidden;"><font size="-1"><div dir="ltr"><div style="font-family:Calibri,Arial,Helvetica,sans-serif;font-size:12pt;color:rgb(0,0,0)">      <img size="92297" width="111" height="62.35955056179775" style="color:rgb(0,0,0);font-family:Calibri,Arial,Helvetica,sans-serif;font-size:12pt;width:111px;height:62.3596px" src="?ui=2&amp;ik=0e761d1ec2&amp;view=fimg&amp;th=16da6a08ffb6561f&amp;attid=0.0.1&amp;disp=emb&amp;attbid=ANGjdJ-Yr8lVSh0rEzdJKOuvRGll_NVDThYl7ft6z3KeU06-LysJssPjoFvwwodCyzZ0KBLLuiydLD-LuCN2w_3T5BBEyDifGhTEiLbBNES70M7mxOVJhGNndY06Q-Q&amp;sz=w222&amp;ats=1570776137534&amp;rm=16da6a08ffb6561f&amp;zw&amp;atsh=1"><br>      </div>      <div>      <div>      <div id="m_-2812952438596108742Signature">      <div>      <div>      <div id="m_-2812952438596108742Signature">      <div>      <div>      <div style="font-family:Calibri,Arial,Helvetica,sans-serif;font-size:12pt;color:rgb(0,0,0)">      <br>      </div>      <div style="font-family:Calibri,Arial,Helvetica,sans-serif;font-size:12pt;color:rgb(0,0,0)">      <div style="margin:0px;font-size:11pt;font-family:sans-serif;color:black;background-color:rgb(255,255,255);direction:rtl">      היי<br>      </div>      <div style="margin:0px;font-size:11pt;font-family:sans-serif;color:black;background-color:rgb(255,255,255);direction:rtl">      שמחה להודיע לך שההרשמה שלך עברה בהצלחה,<br>      </div>      <div style="margin:0px;font-size:11pt;font-family:sans-serif;color:black;background-color:rgb(255,255,255);direction:rtl">      מצורפים קבצים לסוכן המתחיל,<br>      </div>      <div style="margin:0px;font-size:11pt;font-family:sans-serif;color:black;background-color:rgb(255,255,255);direction:rtl">      נקווה לשיתוף פעולה ארוך טווח.<br>      </div>      <div style="margin:0px;font-size:11pt;font-family:sans-serif;color:black;background-color:rgb(255,255,255)">      <div style="text-align:center"><a href="https://j4u.work/" rel="noopener noreferrer" style="color:rgb(17,85,204)" target="_blank" data-saferedirecturl="https://www.google.com/url?hl=en&amp;q=https://j4u.work/&amp;source=gmail&amp;ust=1570862537537000&amp;usg=AFQjCNGeTJF-NMG5oUvx15euEGrDcFVJeA"><b>https://j4u.work</b></a></div>      </div>      <br>      <br>      </div>      <div style="font-family:Calibri,Arial,Helvetica,sans-serif;font-size:12pt;color:rgb(0,0,0)">      <br>      </div>      <div id="m_-2812952438596108742Signature">      <div></div>      <div style="text-align:right;direction:rtl;font-family:Calibri,Arial,Helvetica,sans-serif;font-size:12pt;color:rgb(0,0,0)">      <b>      <div style="margin:0px;font-weight:400;font-size:12pt;font-family:Calibri,Arial,Helvetica,sans-serif;background-color:rgb(255,255,255)">      <i><br>      </i></div>      <div style="margin:0px;font-weight:400;font-size:12pt;font-family:Calibri,Arial,Helvetica,sans-serif;background-color:rgb(255,255,255)">      <i>לשאלות מוזמנים לכתוב במייל חוזר או ל whats app</i></div>      <div style="margin:0px;font-weight:400;font-size:12pt;font-family:Calibri,Arial,Helvetica,sans-serif;background-color:rgb(255,255,255)">      <i>0547323593&nbsp;&nbsp;</i></div>      </b></div>      <div style="text-align:right;direction:rtl;font-family:Calibri,Arial,Helvetica,sans-serif;font-size:12pt;color:rgb(0,0,0)">      <b>בברכה</b></div>      <div style="text-align:right;direction:rtl;font-family:Calibri,Arial,Helvetica,sans-serif;font-size:12pt;color:rgb(0,0,0)">      <b>ולרי</b></div>      </div></div></div></div></div></div></div></div></div></div> </font></div>`
      // };
      // transporter.sendMail(options, function(error, info){
      //     if (error) {
      //       console.log(error);
      //     } else {
      //       console.log('Email sent: ' + info.response);
      //     }
      //   });


      res.json({ user, msg: 'account created successfully' });
    });
  });

  app.post("/auth/request-pass", (req, res, next) => {
      mailOptions.text = req.body.email + "  requested password reset";
      transporter.sendMail(mailOptions, function(error, info){
          if (error) {
            console.log(error);
          } else {
            console.log('Email sent: ' + info.response);
          }
        });
        
      res.json({});
  });

  app.post("/contactForm",(req, res, next) => {
    var body = req.body;
    var sql = `INSERT INTO ContactUs  (CustomerName,Email,Message, PhoneNumber) Values(?,?,?,?)`;
      var userData = [body.CustomerName, body.Email, body.Message, body.PhoneNumber ];
      con.query(sql,userData, function (err, result) {
        if (err) throw err;
        res.json({});  
      });
  })
  //TODO ADD PROTECTION FOR USER TYPE > 1 ONLY
  app.post("/searchJobCandidates",passport.authenticate('jwt', { session: false }),(req, res, next) => {
    var body = req.body;
    var sql = `SELECT c.Id CandidateId, Concat(c.FirstName,' ', c.LastName) AS candidateName,
                c.email AS candidateMail, c.PhoneNumber AS candidatePhoneNumber,
                j.id as JobId,jc.Id as JobCandidateId, jc.jobName,jc.CreateDate, jc.status AS candidateStatus, jc.StatusDescription statusDescription,
                u.fullName AS agentName, u.email AS agentMail, u.phoneNumber AS agentPhoneNumber,c.IsFromPool
                FROM candidate c
                LEFT JOIN jobcandidate jc ON c.Id  = jc.CandidateId
                LEFT JOIN users u ON jc.userid = u.id 
                LEFT JOIN job j ON jc.JobId = j.id        
                WHERE j.company = 'hr'                
                AND c.PhoneNumber = '${body.q}'
                OR c.Email = '${body.q}'
                OR j.Categories like '%${body.q}%'
                OR Concat(c.FirstName,' ', c.LastName) like '%${body.q}%'`;
      con.query(sql, function (err, result) {
        if (err) throw err;
        res.json(result);  
      });
  })


  sendMessageToBot = function(status,d){
    if(status === "Accepted"){
      bot.sendMessage(-206212060, `מועמד מספר ${d.jobCandidateId} התקבל למשרה `);
    }
    if(status === "Resume sent"){
      bot.sendMessage(-206212060, `מועמד מספר ${d.jobCandidateId} נשלח קורות חיים `);
    }
  }
  process.on('uncaughtException', function(err) {
      logger.error('Caught exception: ' + err);
    });