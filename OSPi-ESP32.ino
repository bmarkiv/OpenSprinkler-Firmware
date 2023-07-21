//#define I2C_SCANNER

#include <WiFi.h>
#include <WiFiClient.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <Update.h>

#include "STASSID.h"

#define HIGH	             1
#define LOW		             0

#if 0 
// Will use this info for connection mapping to ESP32
// OSPI            PI GPIO #  //  pin name    //   pin # 
#define PIN_SR_CLOCK       4  //        D6    //       7 - shift register clock pin 
#define PIN_SR_OE         17  //        A1    //      11 - shift register output enable pin
#define PIN_SR_DATA       27  //        D5    //      13 - shift register data pin
#define PIN_SR_LATCH      22  //        D7    //      15 - shift register latch pin
#else
// ESP32              GPIO #
#define PIN_SR_CLOCK      16    // shift register clock pin
#define PIN_SR_OE         17    // shift register output enable pin
#define PIN_SR_DATA       18                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            // shift register data pin
#define PIN_SR_LATCH      19    // shift register latch pin
#endif

int clock_delay = -1;

long sr_state = 0;
unsigned long station_off_time = 0;

void shift_register_setup(){
	pinMode(PIN_SR_OE, OUTPUT);
	// pull shift register OE high to disable output
	digitalWrite(PIN_SR_OE, HIGH);

	pinMode(PIN_SR_LATCH, OUTPUT);
	digitalWrite(PIN_SR_LATCH, HIGH);

	pinMode(PIN_SR_CLOCK, OUTPUT);
	pinMode(PIN_SR_DATA, OUTPUT);

	apply_all_station_bits(0);

	// pull shift register OE low to enable output
	digitalWrite(PIN_SR_OE, LOW);
}

void apply_all_station_bits(long state){
  sr_state = state;

	// Shift out all station bit values from the highest bit to the lowest
  long test_bit = 1 << 23;
  digitalWrite(PIN_SR_LATCH, LOW);
  for(int i=0; i < 24; i++, test_bit >>= 1) {
    digitalWrite(PIN_SR_DATA, (state & test_bit) ? HIGH : LOW ); 
    digitalWrite(PIN_SR_CLOCK, LOW); 
    if (clock_delay > -1) delay(clock_delay); 
    digitalWrite(PIN_SR_CLOCK, HIGH);
  }
  digitalWrite(PIN_SR_LATCH, HIGH);
}

static char b_temp[128];

bool change_state(long station, bool on){
    if (station > 0 && station < 25){
      long station_bit = 1 << station - 1;
      apply_all_station_bits(on ? sr_state | station_bit : sr_state & ~station_bit);
    } else {
        snprintf(b_temp, sizeof(b_temp)-1, "Invalid station number: %d", station); Serial.println(b_temp);
        apply_all_station_bits(0);
        return false;
    }
    return true;
}
bool change_state(const char* uri, bool on){
  long station = atol(uri);
  // check if there is extra parameter (max duration)
  if (on) {
    while (*uri && *uri != '&')uri++;
    long max_duration = *uri == '&' ? atol(uri + 1) : 0;
    if (max_duration != -1){ // if station is not master
      station_off_time = max_duration > 0 ? millis() + max_duration * 1000 : 0;
    }
  } else {
    station_off_time = 0;
  }

  return change_state(station, on);
}

// -------------------------------------------------------------------
WebServer server(80);

String message;
String uri_station_on = "/+";
String uri_station_off = "/-";

const char *html_body_start = "<html>" \
"<head>" \
  "<style>" \
    "body" \
        " { background-color: #cccccc; font-family: Arial, Helvetica, Sans-Serif; Color: #000088; }" \
  "</style>" \ 
"</head>" \
"<body>" \
  "<h1>OpenSprinkler-ESP32 1.0</h1>" 
;
const char *url_format = "<p>Statin control URL format:-[station number]</p>";

const char *html_body_end = "</body></html>";

const char *Uptime() {
  unsigned long sec = millis() / 1000;
  unsigned long min = sec / 60;
  unsigned long hr = min / 60;
  unsigned long d = hr / 24;

  snprintf(b_temp, sizeof(b_temp)-1, "<h2>State: %x</h2><p>Uptime: %d %02d:%02d:%02d</p>", sr_state, d, hr % 24, min % 60, sec % 60);
  message += b_temp;
  message += url_format;
  return b_temp;
}
void handleNotFound() {
  message = html_body_start;
  String uri = server.uri();
  Serial.print("uri: "); Serial.println(uri);
  bool station_on = uri.startsWith(uri_station_on);
  bool station_off = uri.startsWith(uri_station_off);
  if ((!station_on && !station_off) || !change_state(uri.c_str() + uri_station_on.length(), station_on)) {
    Serial.print("Invalid uri: ");  Serial.println(uri);
    message += "<h1>Invalid uri: " + uri + "</h1>";
  }

  Uptime();
  message += html_body_end;

  server.send(200, "text/html", message);
}

void web_server_init() {
  server.on("/", HTTP_GET, []() {
      server.sendHeader("Connection", "close");
      message = html_body_start;
      Uptime();
      message += "<div style='border: 2px solid; margin: 40px 0px; width: 400px'>" \
          "<div style='margin: 20px' >" \
          "<h2>Firmware update:</h2>" \
          "<form method='POST' action='/update' enctype='multipart/form-data'>" \
            "<input type='file' name='update'>" \
            "<input type='submit' value='Upload'>" \
          "</form>" \
        "</div></div>";
      message += html_body_end;
      server.send(200, "text/html", message);
  });  
  server.on("/update", HTTP_POST, []() {
      server.sendHeader("Connection", "close");
      Serial.println("ESP.restart()");
      message = html_body_start;
      message += "<h1>Status of OTA update - "; message += Update.hasError() ? "FAIL" : "OK"; message += "</h1>";
      Uptime();
      message += html_body_end;
      server.send(200, "text/html", message);
      delay(2);
      ESP.restart();
    }, []() {
      Serial.print("server.upload()...");
      HTTPUpload& upload = server.upload();
      Serial.printf(" upload.status - %d\n", upload.status);
      if (upload.status == UPLOAD_FILE_START) {
        Serial.setDebugOutput(true);
        Serial.printf("Update: %s\n", upload.filename.c_str());
        if (!Update.begin()) { //start with max available size
          Update.printError(Serial);
        }
      } else if (upload.status == UPLOAD_FILE_WRITE) {
        if (Update.write(upload.buf, upload.currentSize) != upload.currentSize) {
          Update.printError(Serial);
        }
      } else if (upload.status == UPLOAD_FILE_END) {
        if (Update.end(true)) { //true to set the size to the current progress
          Serial.printf("Update Success: %u\nRebooting...\n", upload.totalSize);
        } else {
          Update.printError(Serial);
        }
        Serial.setDebugOutput(false);
      } else {
        Serial.printf("Update Failed Unexpectedly (likely broken connection): status=%d\n", upload.status);
      }
    });
  server.onNotFound(handleNotFound);
  server.begin();
  Serial.println("HTTP server started");
}

//-------------------------------------------------------------------
void setup(void) {
  shift_register_setup();
  Serial.begin(115200);

  WiFi_init();
  web_server_init();
}

long c = 0;
int val = 1;
void loop(void) {
  server.handleClient();
  delay(2);  //allow the cpu to switch to other tasks
  //---------------------------------------------------
  // check max statin time and turn it off in case timeout (OSPi crashed, WiFi lost, etc.)
  if (station_off_time && c++ % 500 == 0){
    if (millis() > station_off_time){
      apply_all_station_bits(0);
      station_off_time = 0;
    }
  }
  
  #if 0
  if (c++ % 500 == 0){
    apply_all_station_bits(val);
    val = val > 1 ? 1 : sr_state;
  }
  #endif
}
