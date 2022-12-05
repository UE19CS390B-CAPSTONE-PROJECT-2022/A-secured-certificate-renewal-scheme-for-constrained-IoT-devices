const crypto = require('crypto');
const express = require('express')
const mysql = require('mysql')
const app = express()
const port = 3000
//import * as x509 from "@peculiar/x509"
//certificate

var rs = require("jsrsasign");
var fs = require("fs");
var forge = require('node-forge');
const { isError } = require('util');
const { Console } = require('console');

// STEP2. specify certificate parameters
let generate_certificate = function(date){
// STEP1. generate a key pair

var kp = rs.KEYUTIL.generateKeypair("EC", "secp256r1");
var prv = kp.prvKeyObj;
var pub = kp.pubKeyObj;
var prvpem = rs.KEYUTIL.getPEM(prv, "PKCS8PRV");
var pubpem = rs.KEYUTIL.getPEM(pub, "PKCS8PUB");
date.setFullYear(date.getFullYear() - 1);
var x = new rs.KJUR.asn1.x509.Certificate({
  version: 3,
  serial: {int: 4},
  issuer: {str: "CA"},
  validity:  new Date(String(date)),
  subject: {str: "Certificate Authority"},
  sbjpubkey: pub, // can specify public key object or PEM string
  ext: [
    {extname: "basicConstraints", cA: false},
    {extname: "keyUsage", critical: true, names:["digitalSignature"]},
    {extname: "cRLDistributionPoints",
     array: [{fulluri: 'http://example.com/a.crl'}]}
  ],
  sigalg: "SHA256withECDSA",
  cakey: prv // can specify private key object or PEM string
});

// you can modify any fields until the certificate is signed.
x.params.subject = {str: "/CN=User2"};
const cert = x.getPEM();
return [prvpem , pubpem , cert , x.params.validity];
}

// STEP3. show PEM strings of keys and a certificate
//console.log(prvpem);
//console.log(pubpem);
//console.log(x.getPEM()); // certificate object is signed automatically with "cakey" value.

// certificate

const db = mysql.createConnection({
  host:'localhost',
  user:'root',
  password:'',
  database:'certificateauthority'
})

db.connect(err => {
  if (err) throw err;
  console.log("Database connected"); 
})

        

app.use(express.json());

let cipher_iv;
let cipher_key;

const encrypt = (publicKey, text) => {
  const buffer = Buffer.from(text, "utf8");
  const encryptOptions = {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PADDING
  }

  const encrypted = crypto.publicEncrypt(encryptOptions, buffer);
  return encrypted.toString("base64");
}
 
let aesEncrypt = function(text){
    const cipher = crypto.createCipheriv('aes-128-cbc',cipher_key,cipher_iv)
    text = new Buffer.from(text)
    var crypted = cipher.update(text,'utf-8','base64')
    crypted += cipher.final('base64');
    return crypted;
}

let aesDecrypt = function(text){
    const decipher = crypto.createDecipheriv('aes-128-cbc',cipher_key,cipher_iv)
    let dec = decipher.update(text,'base64','utf-8')
    dec += decipher.final();
    return dec;
}


app.post('/get_keys', (req, res) => {
  
  cipher_iv = crypto.randomBytes(16); // IV
  cipher_key = crypto.randomBytes(16);

  const public_key = req.body.public_key;
  var id = req.body.id;
  let sql = "select id from nodes where id = " + mysql.escape(id);
  db.query(sql,(err,result) => {
    if (err) throw err;
    if (result.length) {
      console.log("Node requesting for keys: " , id);
      console.log("The keys generated for communication are");
      console.log("cipher_iv:" , cipher_iv);
      console.log("cipher_key:" , cipher_key);
      console.log();
      console.log();
      let data = Buffer.concat([cipher_key, cipher_iv]);
      const resp = encrypt(public_key, data);
      res.send(JSON.stringify({key: resp}));
    }
    else{
      console.log("node id not verified");
      res.send(JSON.stringify({key: "Node not recognised"}));
    }
  })
  
})

app.post('/request',(req,res) =>{
  console.log("Encrypted message from the Node:");
  console.log(req.body.request);
  console.log();
  const request = aesDecrypt(req.body.request);
  console.log("Decrypted request from the Node: ");
  console.log(request);
  console.log();
  const response_1 = JSON.parse(request);
  const public_key=response_1["public_key"];
  var id = response_1["id"];
  let sql = "select id from nodes where id = " + mysql.escape(id);
  db.query(sql,(err,result) => {
    if (err) throw err;
    if (result.length) {
      const [private_key,pub_key,certificate,validity]=generate_certificate(new Date());
      var insert_data = {id:id,private_key: private_key,public_key:pub_key,certificate:certificate,validity:validity};
      values = [[String(id),String(private_key),String(pub_key),String(certificate),validity]];
      let sql_1 = "INSERT INTO issuedcertificates(id,privatekey,publickey,certificate,validity) VALUES ?";
      db.query(sql_1,[values],(err,result_1) => {
        if (err) throw err;
        let data=JSON.stringify({private_key: private_key,public_key:pub_key,certificate:certificate});
        let start_2=Date.now();
        let enc_data=aesEncrypt(data);
        let finish_2=Date.now();
        console.log("Certicate and the Keys generated are");
        console.log(private_key);
        console.log();
        console.log(pub_key);
        console.log();
        console.log(certificate);
        res.send(JSON.stringify({result: {response: enc_data}}));  
      })  
    }
    else{
      console.log("node id not verified");
      res.send(JSON.stringify({key: "Node does not belong to the Network"}));
    }
  })
  
  
  })

app.post('/renew',(req,res) =>{
  let start=Date.now();
  const request = aesDecrypt(req.body.request);
  let finish=Date.now();
  console.log("Decrypted request from the Node: ");
  console.log(request);
  console.log();
  const response_1 = JSON.parse(request);
  const public_key=response_1["public_key"];
  const id=String(response_1["id"]);
  const certificate=String(response_1["certificate"]);
  //var value=[]
  let sql = "select id from nodes where id = " + mysql.escape(id);
  db.query(sql,(err,result) => {
    if (err) throw err;
    if (result.length) {
      console.log("Node_id:" , id);
      let sql_1 = "select * from issuedcertificates where certificate = " + mysql.escape(certificate);
      db.query(sql_1,(err,result_1) => {
        if (err) throw err;
        Object.keys(result_1).forEach(function(key){
          var row = result_1[key];
          var cert=row.certificate;
          if(certificate==cert){
          expiry = new Date(row.validity);
          new_date=new Date();
          console.log(expiry);
          console.log(new_date);
          if(new_date>expiry){
            let start_1=Date.now();
            const [private_key,pub_key,certificate,validity]=generate_certificate(new Date());
            let finish_1=Date.now();
            var insert_data = {id:id,private_key: private_key,public_key:pub_key,certificate:certificate,validity:validity};
            values = [[String(id),String(private_key),String(pub_key),String(certificate),String(validity)]];
            let sql_1 = "INSERT INTO renewdcertificates(id,privatekey,publickey,certificate,validity) VALUES ?";
            db.query(sql_1,[values],(err,result_3) => {
            if (err) throw err;
            console.log("New certificate are keys are issued");
            console.log(private_key);
            console.log();
            console.log(pub_key);
            console.log();
            console.log(certificate);
            let data=JSON.stringify({private_key: private_key,public_key:pub_key,certificate:certificate});
            let enc_data=aesEncrypt(data);
       
            res.send(JSON.stringify({result: {response: enc_data}}));  
            })

          }
          else{
            console.log("Certificate is still valid");
            res.send(JSON.stringify({result: {response: aesEncrypt("Valid")}}));
          }
        }
        else{
          console.log("Certicate not issued");
        }
        });
      })  
    }
    else{
      console.log("node id not verified");
      res.send(JSON.stringify({key: "Node does not belong to the Network"}));
    }
  })

})

app.post('/revoke',(req,res) =>{
  let start=Date.now();
  const request = aesDecrypt(req.body.request);
  let finish=Date.now();
  console.log("Decrypted request from ESP8266: ");
  console.log(request);
  const response_1 = JSON.parse(request);
  const public_key=response_1["public_key"];
  const id=String(response_1["id"]);
  const certificate=String(response_1["certificate"]);
  //var value=[]
  let sql = "select id from nodes where id = " + mysql.escape(id);
  db.query(sql,(err,result) => {
    if (err) throw err;
    console.log(result);
    if (result.length) {
      console.log("Node_id:" , id);
      let sql_1 = "select * from certificates where certificate = " + mysql.escape(certificate);
      db.query(sql_1,(err,result_1) => {
        if (err) throw err;
        Object.keys(result_1).forEach(function(key){
          var row = result_1[key];
          var cert=row.certificate;
          if(certificate==cert){
            console.log("The certificate has been revoked");
          }
          else{
            console.log("Certificate is not revoked and valid for communication");
          }
        })
        });
      }  
    else{
      console.log("node id not verified");
      res.send(JSON.stringify({key: "Node does not belong to the Network"}));
    }
  })

})

app.post('/send_data', (req, res) => {  
    console.log("Encrypted data from Node using the certificate anf keys generated");
    console.log(req.body.request);
    console.log();
    const request = aesDecrypt(req.body.request);
    console.log("Decrypted data from Node: ");
    const msg=JSON.parse(request);
    console.log("Device id: ",msg["Device_name"]);
    console.log(msg["Organisation"]);
    console.log(msg["Department"]);
    console.log("Value:",msg["Value"]);
    console.log(msg["Country"]);
    // Do the login here.  Prepare the response
    let data = JSON.stringify({message:"value received"});
    res.send(JSON.stringify({result: {response: aesEncrypt(data)}}));
})

app.listen(3000, () => {
  console.log(`Listening at http://localhost:${port}`)
})
