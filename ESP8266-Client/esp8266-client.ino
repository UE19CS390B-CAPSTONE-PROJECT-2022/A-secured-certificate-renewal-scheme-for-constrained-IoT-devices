#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <SPI.h>
#include <Crypto.h>
#include "Base64.h"
#include "Hash.h"
#include <Arduino_JSON.h>


// WiFi config
const char WIFI_SSID[] = "DINESH";
const char WIFI_PASS[] = "8553989108";

uint8_t _cipher_key[16], _cipher_iv[16];
const char* certificate_1[2048];

const char rsa_private_key[] = R"EOF(
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDyvUGig/COqXeX3OUk9bo6qewURHbZT9JvjbrhPHJ55ou/4Ets
MND5BcsEspQTEniG38oWyHMPjfGe9Ogh4KXFGFH9gdEIiWqSd61/Hwu/vKRAz/uP
00V7aato+JfYjNLOg6ek+dlmSoE7JDmpSjFJoqMwjkERUeqqsnahi/I9IwIDAQAB
AoGAUdcdWf3CDVd1yu3fFCcFMuI3hl3O9FXFTXcrmuUWc6MXWwn0Y/XRfyRE3sCW
zBdeK5soN6Y9pPDmlgFcgo+LU9BXF1idmj+EtcTwyIwsEQWqdokUjx2noXujdOaJ
UoAbJJB1D0EINpBYVojEI2n0QrA9bcgboEtrMoxBuBW5igECQQD5ikX+oT1xIGV3
/8qRkYUnC51P4um8mMRRy1m72oc14NJE7usEcn8syaLAqBExiiiKUTHu2xi2u2eD
kd9ee2aRAkEA+QXpwHzgE0v33sqnDkIX5kkoXyggCc5HFxOWQiLMIfS2OZrifBTh
RTbd5BgIo8dsTeRG2pvRObsOouM5qCmKcwJBAKesJYQGy8YrwoJzOaW+Zf3qa/W1
vuCetatQPCdhmuC1BBSVhQ0j8hgiFF3nkEX9U2g9TpP0XBLMsa1SYwiVWkECQFlY
z8eqhlMmHKcpGss4145ejUenA+fAxSz4cB8GkStVu9PrSHuwmirVRsPCA8ePk8JW
tz1UTrth7BxxXoyBaxUCQEOE9ZpmFfJLyZ1AVUVvPpEP3sGGPIvu5Px0ODtUE19Y
vlEOhvlRoygbGl67EmTo6Jh44isuBB8HQMjV1turFjk=
-----END RSA PRIVATE KEY-----

)EOF";





const char rsa_public_key[] = R"EOF(
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDyvUGig/COqXeX3OUk9bo6qewU
RHbZT9JvjbrhPHJ55ou/4EtsMND5BcsEspQTEniG38oWyHMPjfGe9Ogh4KXFGFH9
gdEIiWqSd61/Hwu/vKRAz/uP00V7aato+JfYjNLOg6ek+dlmSoE7JDmpSjFJoqMw
jkERUeqqsnahi/I9IwIDAQAB
-----END PUBLIC KEY-----
)EOF";


HTTPClient http;
WiFiClient client;
const int sensor_pin=A0;
void setup()
{
  Serial.begin(115200);
  Serial.println("Starting...");  
 
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  Serial.print("Waiting for WiFi connection.");
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(500);
  }
  Serial.println(" Finished !");
  

  delay(100);

  get_keys(rsa_private_key, rsa_public_key);
  request(rsa_private_key, rsa_public_key);
  ;
  Serial.println("Ready for communication !");  
  
}
 
void loop()
{
  
}
void request(const char private_key[], const char public_key[]) {  
  http.begin(client,"http://192.168.1.6:3000/request");
  http.addHeader("Content-Type", "application/json");

  JSONVar payload;
  payload["public_key"] = public_key;
  String id = WiFi.macAddress();
  String hashed = sha1(id);
  Serial.println(hashed);
  payload["id"] = hashed;

  String payload_str = JSON.stringify(payload);
  String encrypted_payload = aes_128_cbc_encrypt(payload_str);

  payload = JSONVar();
  payload["request"] = encrypted_payload;
 
  payload_str = JSON.stringify(payload);
  http.POST(payload_str);
  Serial.println();
  Serial.println("Encrypted Data sent to CA:");
  Serial.println(payload_str);
  Serial.println();
  payload_str = http.getString();
  payload = JSON.parse(payload_str);
  String response = (const char *)payload["result"]["response"];
  JSONVar res;
  String decrypted_response_str = aes_128_cbc_decrypt(response);
  res=JSON.parse(decrypted_response_str);
  Serial.println("Certificates and Keys issued by the CA");
  String private_1 = (const char*)res["private_key"];
  String public_1 = (const char*)res["public_key"];
  String certificate = (const char* )res["certificate"];
  Serial.println(private_1);
  Serial.println(public_1);
  Serial.println(certificate);
  int issue = 0;
  if (certificate.length() > 0){
    issue = 1;
    Serial.println("Certificate issued");
    Serial.println("Eligible for renewal");
  }
  if (issue == 1){
    delay(8000);
   renew(rsa_private_key, rsa_public_key,certificate);
   //send_data(hashed,"Chip Technologies","Moisture Monitoring","India");
  }
}

void renew(const char private_key[], const char public_key[], String certificate) {  
  http.begin(client,"http://192.168.1.6:3000/renew");
  http.addHeader("Content-Type", "application/json");

  JSONVar payload;
  payload["public_key"] = public_key;
  String id = WiFi.macAddress();
  String hashed = sha1(id);
  Serial.println(hashed);
  payload["id"] = hashed;
  payload["certificate"]=certificate;

  String payload_str = JSON.stringify(payload);
  String encrypted_payload = aes_128_cbc_encrypt(payload_str);
  Serial.println();
  Serial.println("Encrypted Request for Certificate Renewal");
  Serial.println(encrypted_payload);
  payload = JSONVar();
  payload["request"] = encrypted_payload;
  payload_str = JSON.stringify(payload);
  unsigned long s=millis();
  http.POST(payload_str);
  payload_str = http.getString();
  Serial.println();
  Serial.println("Encrypted Certificate Sent by CA");
  Serial.println(payload_str);

  payload = JSON.parse(payload_str);
  String response = (const char *)payload["result"]["response"];
  JSONVar res;
  String decrypted_response_str = aes_128_cbc_decrypt(response);
  res=JSON.parse(decrypted_response_str);
  Serial.println();
  Serial.println("Certificate Issued for the renewal process");
  String private_1 = (const char*) res["private_key"];
  String public_1= (const char*) res["public_key"];
  String certificate_1 = (const char*) res["certificate"];
  if(certificate_1.length()>0){
  Serial.println(private_1);
  Serial.println(public_1);
  Serial.println(certificate_1); 
  }
  else{
    Serial.println("Certificate is still Valid");
  }
}

void get_keys(const char rsa_private_key[], const char rsa_public_key[]) {  
  http.begin(client,"http://192.168.1.6:3000/get_keys");
  http.addHeader("Content-Type", "application/json");

  JSONVar payload;
  payload["public_key"] = rsa_public_key;
  String id= WiFi.macAddress();
  String hashed = sha1(id);
  Serial.print("Node id:");
  Serial.println(hashed);
  payload["id"] = hashed;

  String payload_str = JSON.stringify(payload);
  Serial.println();
  Serial.println("POST message sent to CA to exchange keys:");
  Serial.println(payload_str);
 
  http.POST(payload_str);
  payload_str = http.getString();

  
  Serial.println();
  Serial.println("Encrypted keys generated by CA");
  Serial.println(payload_str);
 
  payload = JSON.parse(payload_str);
  String key_str = (const char *)payload["key"];

  int input_len = key_str.length();
  char *key = const_cast<char*>(key_str.c_str());
  int len = base64_dec_len(key, input_len);
  uint8_t data[len];
  base64_decode((char *)data, key, input_len);

  int i;
//  for(i = 0; i < len; i++) {
//    Serial.printf("%02x", data[i]);
//  }
//  Serial.println();
 
 
  // RSA PKCS#1 V1.5 Padding Encryption
  BearSSL::PrivateKey *private_key_obj = new BearSSL::PrivateKey(rsa_private_key);
 
  (*br_rsa_private_get_default())(data, private_key_obj->getRSA());

  // In RSAES-PKCS1-v1_5, the data begins with 00 02 and ends with 00 eg: 00 02 <encryped> 00
 
  for(i = 2; i < len; i++){
    if(data[i] == 0) break;
  }
  i++;
  len -= i;

  uint8_t decoded_data[len];
  memcpy(decoded_data, &data[i], len);

//  for(i = 0; i < len; i++) {
//    Serial.printf("%02x", decoded_data[i]);
//  }
//  Serial.println();

  // set the Key & IV server generated

  uint8_t b_arr[16], b_arr2[16];
  memcpy(b_arr, decoded_data, 16);        //key
  memcpy(b_arr2, &decoded_data[16], 16);  //iv
 
  aes_128_cbc_init(b_arr, b_arr2);  
}


void send_data(String device,String organisation,String dept,String country) {
  http.begin(client,"http://192.168.1.6:3000/send_data");
  http.addHeader("Content-Type", "application/json");
   
  JSONVar payload;
  payload["Device_name"] = device;
  payload["Organisation"] = organisation;
  payload["Department"] = dept;
  float moisture_percentage;
  moisture_percentage=(100.00-((analogRead(sensor_pin)/1023.00)*100));
  payload["Value"] = moisture_percentage;
  payload["Country"] = country;  

  String payload_str = JSON.stringify(payload);
  String encrypted_payload = aes_128_cbc_encrypt(payload_str);
  Serial.println();
  Serial.println("Encrypted sensor data value being sent to the server:");
  Serial.println(encrypted_payload);

  payload = JSONVar();
  payload["request"] = encrypted_payload;
 
  payload_str = JSON.stringify(payload);
  http.POST(payload_str);
  payload_str = http.getString();
  Serial.println();
  Serial.println("Encrypted Response Message sent by the Server:");
  Serial.println(payload_str);

  payload = JSON.parse(payload_str);
  String response = (const char *)payload["result"]["response"];
  String decrypted_response_str = aes_128_cbc_decrypt(response);
  Serial.println();
  Serial.println(" Decrypted Response Message sent by the Server");
  Serial.println(decrypted_response_str);
}

void aes_128_cbc_init(uint8_t b_arr[], uint8_t b_arr2[]){
  memcpy(_cipher_key, b_arr, 16);
  memcpy(_cipher_iv, b_arr2, 16);
}


String aes_128_cbc_encrypt(String plain_data){
  int i;
  // PKCS#7 Padding (Encryption), Block Size : 16
  int len = plain_data.length();
  int n_blocks = len / 16 + 1;
  uint8_t n_padding = n_blocks * 16 - len;
  uint8_t data[n_blocks*16];
  memcpy(data, plain_data.c_str(), len);
  for(i = len; i < n_blocks * 16; i++){
    data[i] = n_padding;
  }

  // AES CBC Encryption
  uint8_t key[16], iv[16];
  memcpy(key, _cipher_key, 16);
  memcpy(iv, _cipher_iv, 16);

  // encryption context
  br_aes_big_cbcenc_keys encCtx;

  // reset the encryption context and encrypt the data
  br_aes_big_cbcenc_init(&encCtx, key, 16);
  br_aes_big_cbcenc_run( &encCtx, iv, data, n_blocks*16 );

  // Base64 Encode
  len = n_blocks*16;
  char encoded_data[ base64_enc_len(len) ];
  base64_encode(encoded_data, (char *)data, len);
 
  return String(encoded_data);
}


String aes_128_cbc_decrypt(String encoded_data_str){  
  // Base64 Decode
  int input_len = encoded_data_str.length();
  char *encoded_data = const_cast<char*>(encoded_data_str.c_str());
  int len = base64_dec_len(encoded_data, input_len);
  uint8_t data[ len ];
  base64_decode((char *)data, encoded_data, input_len);
 
  // AES CBC Decryption
  uint8_t key[16], iv[16];
  memcpy(key, _cipher_key, 16);
  memcpy(iv, _cipher_iv, 16);

  int n_blocks = len / 16;

  br_aes_big_cbcdec_keys decCtx;

  br_aes_big_cbcdec_init(&decCtx, key, 16);
  br_aes_big_cbcdec_run( &decCtx, iv, data, n_blocks*16 );  //Important ! iv mo swap.

  // PKCS#7 Padding (Decryption)
  uint8_t n_padding = data[n_blocks*16-1];
  len = n_blocks*16 - n_padding;
  char plain_data[len + 1];
  memcpy(plain_data, data, len);
  plain_data[len] = '\0';

  return String(plain_data);
}
